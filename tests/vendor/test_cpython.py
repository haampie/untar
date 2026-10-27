# Adapted from CPython's Lib/test/test_tarfile.py and its test archives, at commit
# be41ce5d591ef267bd8e56b6897101562b1e1982 of https://github.com/python/cpython, under the
# PSF License Agreement below.
#
# Copyright (c) 2001 Python Software Foundation; All Rights Reserved
#
# Summary of changes: the read tests (UstarReadTest, MemberReadTest, LongnameTest, GNUReadTest,
# PaxReadTest, StreamReadTest, DetectReadTest) are recast as comparisons of untar's reader with
# tarfile on CPython's testtar.tar, which is not included and is read from
# UNTAR_CPYTHON_TESTDATA. The attacks of TestExtractionFilters keep their archives, built by
# a port of its ArchiveMaker, but check untar's guarantee instead of tarfile's filters:
# nothing outside the destination is created, changed or read, whether untar extracts the
# archive or refuses it. Tests are written for pytest.
#
# PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2
# --------------------------------------------
#
# 1. This LICENSE AGREEMENT is between the Python Software Foundation
# ("PSF"), and the Individual or Organization ("Licensee") accessing and
# otherwise using this software ("Python") in source or binary form and
# its associated documentation.
#
# 2. Subject to the terms and conditions of this License Agreement, PSF hereby
# grants Licensee a nonexclusive, royalty-free, world-wide license to reproduce,
# analyze, test, perform and/or display publicly, prepare derivative works,
# distribute, and otherwise use Python alone or in any derivative version,
# provided, however, that PSF's License Agreement and PSF's notice of copyright,
# i.e., "Copyright (c) 2001 Python Software Foundation; All Rights Reserved"
# are retained in Python alone or in any derivative version prepared by Licensee.
#
# 3. In the event Licensee prepares a derivative work that is based on
# or incorporates Python or any part thereof, and wants to make
# the derivative work available to others as provided herein, then
# Licensee hereby agrees to include in any such work a brief summary of
# the changes made to Python.
#
# 4. PSF is making Python available to Licensee on an "AS IS"
# basis.  PSF MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR
# IMPLIED.  BY WAY OF EXAMPLE, BUT NOT LIMITATION, PSF MAKES NO AND
# DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS
# FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF PYTHON WILL NOT
# INFRINGE ANY THIRD PARTY RIGHTS.
#
# 5. PSF SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF PYTHON
# FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS
# A RESULT OF MODIFYING, DISTRIBUTING, OR OTHERWISE USING PYTHON,
# OR ANY DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.
#
# 6. This License Agreement will automatically terminate upon a material
# breach of its terms and conditions.
#
# 7. Nothing in this License Agreement shall be deemed to create any
# relationship of agency, partnership, or joint venture between PSF and
# Licensee.  This License Agreement does not grant permission to use PSF
# trademarks or trade name in a trademark sense to endorse or promote
# products or services of Licensee, or any third party.
#
# 8. By copying, installing or otherwise using Python, Licensee
# agrees to be bound by the terms and conditions of this License
# Agreement.

"""Tests adapted from CPython's test_tarfile.py: reading CPython's test archive like tarfile, and
CPython's extraction attacks, which may not create, change or read anything outside the
destination. See the notice above."""

import collections
import hashlib
import io
import os
import stat
import sys
import tarfile

import pytest

import untar

TESTDATA = os.environ.get("UNTAR_CPYTHON_TESTDATA")
needs_testdata = pytest.mark.skipif(not TESTDATA, reason="needs UNTAR_CPYTHON_TESTDATA")
needs_symlinks = pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")


def snapshot(root):
    """The tree below root: types, executable bits, contents, link targets, hardlinks."""
    out = {}
    inodes = collections.defaultdict(set)
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            s = os.lstat(path)
            if stat.S_ISLNK(s.st_mode):
                out[rel] = ("s", os.readlink(path))
            elif stat.S_ISDIR(s.st_mode):
                out[rel] = ("d",)
            else:
                with open(path, "rb") as f:
                    out[rel] = ("f", bool(s.st_mode & 0o100), f.read())
                inodes[(s.st_dev, s.st_ino)].add(rel)
    out["<hardlinks>"] = sorted(
        sorted(group) for group in inodes.values() if len(group) > 1
    )
    return out


# Reading CPython's test archive


sha256_regtype = "e09e4bc8b3c9d9177e77256353b36c159f5f040531bbd4b024a8f9b9196c71ce"
sha256_sparse = "4f05a776071146756345ceee937b33fc5644f5a96b9780d1c7d6a32cdf164d7b"

#: untar extracts only regular files, dirs and links, and rejects sparse and contiguous files
UNSUPPORTED = (
    tarfile.CHRTYPE,
    tarfile.BLKTYPE,
    tarfile.FIFOTYPE,
    tarfile.GNUTYPE_SPARSE,
    tarfile.CONTTYPE,
)


def read_testtar() -> bytes:
    with open(os.path.join(TESTDATA, "testtar.tar"), "rb") as f:
        return f.read()


def raw_members(data: bytes):
    """Yield the tarfile member and the raw bytes of its headers and data."""
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        members = tar.getmembers()
        ends = [m.offset for m in members[1:]] + [tar.offset]
    for member, end in zip(members, ends):
        yield member, data[member.offset : end]


def unsigned_checksum(header: bytes) -> bool:
    """Whether the checksum of a header is the sum of its bytes, as POSIX says."""
    expected = int(header[148:156].strip(b" \0"), 8)
    return expected == sum(header[:148]) + sum(header[156:]) + 256


def supported(member: tarfile.TarInfo, raw: bytes) -> bool:
    """Whether untar extracts a member, which it does not if tar-minefield rejects it. pax/regtype4
    has a pax size, and 0 as the size in its header, which readers that ignore the pax size read
    (F14). ustar/dirtype-with-size is a dir with a size, which readers skip or take for data
    (F33). The checksums of misc/regtype-*-signed-chksum-* only match as the sum of signed
    bytes, which some readers refuse (F06). Names that are not UTF-8 are created as they are or
    with other bytes (N18)."""
    header = raw[member.offset_data - member.offset - 512 :][:512]
    return (
        member.type not in UNSUPPORTED
        and not member.issparse()
        and "size" not in member.pax_headers
        and not (member.isdir() and member.size)
        and unsigned_checksum(header)
        and utf8(member)
    )


def utf8(member: tarfile.TarInfo) -> bool:
    try:
        member.name.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def without_unsupported(data: bytes) -> bytes:
    """testtar.tar without the members untar does not extract, with every other header kept
    as is."""
    kept = b"".join(raw for member, raw in raw_members(data) if supported(member, raw))
    return kept + bytes(1024)


@needs_testdata
def test_members_like_tarfile():
    """Every member has the name, type, mode, size, link name and data tarfile reads."""
    data = without_unsupported(read_testtar())
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        expected = []
        for m in tar:
            content = tar.extractfile(m).read() if m.isreg() else None
            expected.append(
                (
                    m.name,
                    m.isreg(),
                    m.isdir(),
                    m.issym(),
                    m.islnk(),
                    m.mode,
                    m.size if m.isreg() else 0,
                    m.linkname,
                    content,
                )
            )
    reader = untar.TarReader(io.BytesIO(data))
    actual = []
    for m in reader:
        content = b"".join(reader.chunks()) if m.isreg() else None
        actual.append(
            (
                m.name,
                m.isreg(),
                m.isdir(),
                m.issym(),
                m.islnk(),
                m.mode,
                m.size if m.isreg() else 0,
                m.linkname,
                content,
            )
        )
    assert len(actual) == len(expected) == 24
    for a, e in zip(actual, expected):
        assert a == e, e[0]


@needs_testdata
def test_checksums():
    """MemberReadTest: the data of regular files, including old v7."""
    reader = untar.TarReader(io.BytesIO(without_unsupported(read_testtar())))
    sums = {}
    for m in reader:
        if m.isreg():
            sums[m.name] = hashlib.sha256(b"".join(reader.chunks())).hexdigest()
    for name in [
        "ustar/regtype",
        "misc/regtype-old-v7",
        "misc/regtype-suntar",
        "misc/regtype-xstar",
        "pax/umlauts-\xc4\xd6\xdc\xe4\xf6\xfc\xdf",
        "pax/regtype1",
        "gnu/regtype-gnu-uid",
    ]:
        assert sums[name] == sha256_regtype, name
    assert "ustar/" + "12345/" * 39 + "1234567/longname" in sums
    assert "gnu/" + "123/" * 125 + "longname" in sums
    assert "pax/" + "123/" * 125 + "longname" in sums


@needs_testdata
def test_unsupported_members():
    """Sparse files of each kind, devices, fifos, contiguous files, and what tar-minefield
    rejects, are rejected, each in an archive of its own."""
    rejected = []
    for member, raw in raw_members(read_testtar()):
        if supported(member, raw):
            continue
        with pytest.raises(untar.Error):
            for m in untar.TarReader(io.BytesIO(raw + bytes(1024))):
                if m.type in UNSUPPORTED:
                    raise untar.Error(f"unsupported {m.type!r}")
        rejected.append(member.name)
    assert rejected == [
        "ustar/conttype",
        "ustar/dirtype-with-size",
        "ustar/blktype",
        "ustar/chrtype",
        "ustar/fifotype",
        "ustar/umlauts-\udcc4\udcd6\udcdc\udce4\udcf6\udcfc\udcdf",
        "gnu/sparse",
        "gnu/sparse-0.0",
        "gnu/sparse-0.1",
        "gnu/sparse-1.0",
        "misc/regtype-hpux-signed-chksum-\udcc4\udcd6\udcdc\udce4\udcf6\udcfc\udcdf",
        "misc/regtype-old-v7-signed-chksum-\udcc4\udcd6\udcdc\udce4\udcf6\udcfc\udcdf",
        "pax/regtype4",
        "pax/bad-pax-\udce4\udcf6\udcfc",
        "pax/hdrcharset-\udce4\udcf6\udcfc",
    ]


@needs_testdata
def test_ustar_sparse_is_a_regular_file():
    """ustar/sparse is not sparse in the archive, and is read in full."""
    for member, raw in raw_members(read_testtar()):
        if member.name == "ustar/sparse":
            reader = untar.TarReader(io.BytesIO(raw + bytes(1024)))
            (m,) = [m for m in reader if m.isreg() and b"".join(reader.chunks())]
            assert m.size == 86016


@needs_testdata
def test_extract_like_tarfile(tmp_path):
    """Extracting gives the tree tarfile extracts, with names like ./x and long names."""
    data = without_unsupported(read_testtar())
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        tar.extraction_filter = lambda member, path: member
        tar.extractall(tmp_path / "expected")
    untar.extract(io.BytesIO(data), str(tmp_path / "actual"))
    assert snapshot(tmp_path / "actual") == snapshot(tmp_path / "expected")


@needs_testdata
@pytest.mark.parametrize("name", ["testtar.tar.xz", "recursion.tar"])
def test_unsupported_archives(name):
    """DetectReadTest: compressions other than gzip are not detected; recursion.tar is invalid."""
    with pytest.raises(untar.Error):
        untar.extract(os.path.join(TESTDATA, name), "unused")


@needs_testdata
def test_gzip_and_stream(tmp_path):
    """GzipUstarReadTest and StreamReadTest: the same members from a gzipped, unseekable stream."""
    import gzip

    data = without_unsupported(read_testtar())

    class Stream:
        def __init__(self, data):
            self.f = io.BytesIO(data)

        def read(self, size=-1):
            return self.f.read(min(size, 511) if size >= 0 else 511)

    names = [m.name for m in untar.TarReader(io.BytesIO(data))]
    assert [m.name for m in untar.TarReader(Stream(data))] == names
    untar.extract(Stream(gzip.compress(data)), str(tmp_path))


# The attacks of TestExtractionFilters


class ArchiveMaker:
    """A port of CPython's ArchiveMaker."""

    def __init__(self):
        self.bio = io.BytesIO()
        self.tar = tarfile.TarFile(mode="w", fileobj=self.bio)

    def add(
        self,
        name,
        *,
        type=None,
        symlink_to=None,
        hardlink_to=None,
        mode=None,
        content=None,
    ):
        name = str(name)
        info = tarfile.TarInfo(name)
        data = content.encode() if isinstance(content, str) else (content or b"")
        info.size = len(data)
        if mode is not None:
            info.mode = mode
        if symlink_to is not None:
            type, info.linkname = tarfile.SYMTYPE, str(symlink_to)
        if hardlink_to is not None:
            type, info.linkname = tarfile.LNKTYPE, str(hardlink_to)
        if name.endswith("/") and type is None:
            type = tarfile.DIRTYPE
        if type is not None:
            info.type = type
        self.tar.addfile(info, io.BytesIO(data) if info.isreg() else None)

    def add_raw(self, name, type, linkname):
        """A member as given, like the tests that call tar_w.addfile directly."""
        info = tarfile.TarInfo(name)
        info.type = type
        info.linkname = linkname
        self.tar.addfile(info)

    def data(self) -> bytes:
        self.tar.close()
        return self.bio.getvalue()


@pytest.fixture
def outerdir(tmp_path):
    outer = tmp_path / "outerdir"
    outer.mkdir()
    (outer / "flag").write_text("capture me")
    return outer


def extract(arc, outerdir):
    """Extract, check that nothing outside dest changed, and return the error, if any."""
    flag = outerdir / "flag"
    before = (
        sorted(p.name for p in outerdir.iterdir()),
        flag.stat().st_mode,
        os.stat(outerdir).st_mode,
    )
    dest = outerdir / "dest"
    error = None
    try:
        untar.extract(io.BytesIO(arc.data()), str(dest))
    except (untar.Error, OSError) as e:
        error = e
    after_names = sorted(p.name for p in outerdir.iterdir())
    assert after_names == sorted(set(before[0]) | {"dest"}), "created outside dest"
    assert flag.read_text() == "capture me"
    assert flag.stat().st_mode == before[1] and os.stat(outerdir).st_mode == before[2]
    assert not any(n.startswith(".untar-") for n in os.listdir(dest)), (
        "temporary dir left"
    )
    return error


def rejected(error, kind=untar.Error, match=""):
    assert isinstance(error, kind), error
    assert match in str(error)


@needs_symlinks
def test_benign_file(outerdir):
    arc = ArchiveMaker()
    arc.add("benign.txt")
    assert extract(arc, outerdir) is None
    assert (outerdir / "dest" / "benign.txt").is_file()


@needs_symlinks
def test_absolute(outerdir):
    arc = ArchiveMaker()
    arc.add(outerdir / "escaped.evil")
    rejected(extract(arc, outerdir), match="unsafe path")


@needs_symlinks
def test_parent_dir_out_and_back(outerdir):
    """The data filter extracts this to sub/file; untar rejects any '..'."""
    arc = ArchiveMaker()
    arc.add("../escaped.evil/../dest/sub/file", content="content")
    rejected(extract(arc, outerdir), match="unsafe path")


@needs_symlinks
def test_parent_symlink(outerdir):
    arc = ArchiveMaker()
    arc.add("current", symlink_to=".")
    arc.add("parent", symlink_to="current/..")
    arc.add("parent/evil")
    rejected(extract(arc, outerdir), match="not a directory")


@needs_symlinks
def test_realpath_limit_attack(outerdir):
    """CVE-2025-4517"""
    arc = ArchiveMaker()
    steps = "abcdefghijklmnop"
    max_path_len = os.pathconf(str(outerdir.parent), "PC_PATH_MAX")
    dest_len = len(str(outerdir / "dest")) + 1
    component = "d" * ((max_path_len - dest_len) // (len(steps) + 1))
    path = ""
    for i in steps:
        arc.add(os.path.join(path, component), type=tarfile.DIRTYPE, mode=0o777)
        arc.add(os.path.join(path, i), symlink_to=component)
        path = os.path.join(path, component)
    linkpath = os.path.join(*steps, "l" * 254)
    arc.add(linkpath, symlink_to=os.path.join(*[".."] * len(steps)))
    arc.add("escape", symlink_to=os.path.join(linkpath, ".."))
    arc.add("flaglink", hardlink_to=os.path.join("escape", "flag"))
    arc.add("flaglink", content="overwrite")
    arc.add("escape/newfile", content="new")
    rejected(extract(arc, outerdir), match="not a directory")


@needs_symlinks
def test_parent_symlink2(outerdir):
    arc = ArchiveMaker()
    arc.add("current", symlink_to=".")
    arc.add("current/parent", symlink_to="..")
    arc.add("parent/evil")
    rejected(extract(arc, outerdir), match="not a directory")


@needs_symlinks
def test_absolute_symlink(outerdir):
    arc = ArchiveMaker()
    arc.add("parent", symlink_to=outerdir)
    arc.add("parent/evil")
    rejected(extract(arc, outerdir), match="not a directory")


@needs_symlinks
def test_absolute_hardlink(outerdir):
    arc = ArchiveMaker()
    arc.add("parent", hardlink_to=outerdir / "foo")
    rejected(extract(arc, outerdir), match="unsafe path")


@needs_symlinks
def test_sly_relative0(outerdir):
    arc = ArchiveMaker()
    arc.add("../moo", symlink_to="..//tmp/moo")
    rejected(extract(arc, outerdir), match="unsafe path")


@needs_symlinks
def test_sly_relative2(outerdir):
    arc = ArchiveMaker()
    arc.add("tmp/")
    arc.add("tmp/../../moo", symlink_to="tmp/../..//tmp/moo")
    rejected(extract(arc, outerdir), match="unsafe path")


@needs_symlinks
@pytest.mark.parametrize("kind", ["symlink_to", "hardlink_to"])
def test_normpath_realpath_mismatch(outerdir, kind):
    depth = len((outerdir / "dest").parts) + 5
    deep = "/".join(f"p{i}" for i in range(depth))
    sneaky = "a/" + "../" * depth + "flag"
    arc = ArchiveMaker()
    arc.add("a", symlink_to=deep)
    arc.add("escape", **{kind: sneaky})
    error = extract(arc, outerdir)
    if kind == "hardlink_to":
        rejected(error, match="unsafe path")
    else:
        # A symlink pointing outside is created, and not followed
        assert error is None
        assert os.readlink(outerdir / "dest" / "escape") == sneaky


@needs_symlinks
def test_symlink_trailing_slash(outerdir):
    arc = ArchiveMaker()
    arc.add_raw("x/", tarfile.SYMTYPE, "..")
    arc.add("x/escaped", content="hi")
    rejected(extract(arc, outerdir), match="named like a directory")


@needs_symlinks
@pytest.mark.parametrize("name", ["", ".", "./"])
def test_link_at_destination(outerdir, name):
    arc = ArchiveMaker()
    arc.add_raw(name, tarfile.SYMTYPE, ".")
    rejected(extract(arc, outerdir), match="non-directory")


@needs_symlinks
def test_empty_name_symlink_chain(outerdir):
    arc = ArchiveMaker()
    for name, target in [
        ("", ""),
        ("a/", ".."),
        ("", "dummy"),
        ("", "a"),
        ("b/", ".."),
        ("", "dummy"),
        ("", "a/b"),
    ]:
        arc.add_raw(name, tarfile.SYMTYPE, target)
    arc.add("escaped", content="hi")
    rejected(extract(arc, outerdir), match="non-directory")


@needs_symlinks
def test_deep_symlink(outerdir):
    arc = ArchiveMaker()
    arc.add("targetdir/target", content="abc")
    arc.add("linkdir/hardlink", hardlink_to=os.path.join("targetdir", "target"))
    arc.add("linkdir/symlink", symlink_to=os.path.join("..", "targetdir", "target"))
    assert extract(arc, outerdir) is None
    dest = outerdir / "dest"
    assert (dest / "linkdir" / "hardlink").read_text() == "abc"
    assert os.readlink(dest / "linkdir" / "symlink") == "../targetdir/target"


@needs_symlinks
def test_chains(outerdir):
    arc = ArchiveMaker()
    arc.add("linkdir/symlink", symlink_to="hardlink")
    arc.add("symlink2", symlink_to=os.path.join("linkdir", "hardlink2"))
    arc.add("targetdir/target", content="abc")
    arc.add("linkdir/hardlink", hardlink_to=os.path.join("targetdir", "target"))
    arc.add("linkdir/hardlink2", hardlink_to=os.path.join("linkdir", "symlink"))
    # A hardlink to a symlink is the symlink or its target (S06)
    rejected(extract(arc, outerdir), match="which is a symlink")


@needs_symlinks
def test_sneaky_hardlink_fallback(outerdir):
    arc = ArchiveMaker()
    arc.add("a/t/dummy")
    arc.add("b/")
    arc.add("c", symlink_to=os.path.join("a", "t"))
    arc.add("c/escape", symlink_to=os.path.join("..", "..", "link_here"))
    arc.add("c", symlink_to="b")
    arc.add("boom", hardlink_to=os.path.join("c", "escape"))
    rejected(extract(arc, outerdir), match="not a directory")


@needs_symlinks
def test_sneaky_hardlink_fallback_deep(outerdir):
    """The hardlink would be the symlink at another depth, or its target (S06)."""
    arc = ArchiveMaker()
    arc.add("a/b/s", symlink_to=os.path.join("..", "escape"))
    arc.add("s", hardlink_to=os.path.join("a", "b", "s"))
    rejected(extract(arc, outerdir), match="which is a symlink")


@needs_symlinks
def test_sneaky_hardlink_relocation(outerdir):
    arc = ArchiveMaker()
    arc.add("a/escape", content="decoy")
    arc.add("a/b/s", symlink_to=os.path.join("..", "escape"))
    arc.add("s", hardlink_to=os.path.join("a", "b", "s"))
    rejected(extract(arc, outerdir), match="which is a symlink")


@needs_symlinks
def test_exfiltration_via_symlink(outerdir):
    arc = ArchiveMaker()
    arc.add("escape", symlink_to=os.path.join("link", "link", "..", "..", "link-here"))
    arc.add("link", symlink_to="./")
    assert extract(arc, outerdir) is None


@needs_symlinks
def test_chmod_outside_dir(outerdir):
    arc = ArchiveMaker()
    arc.add("a/pwn", symlink_to=".")
    arc.add("a/pwn/", mode=0o777)
    arc.add("a/pwn", symlink_to="x/../")
    arc.add("a/x", symlink_to="../")
    rejected(extract(arc, outerdir), match="not a directory")


@needs_symlinks
@pytest.mark.parametrize("link_type", [tarfile.SYMTYPE, tarfile.LNKTYPE])
def test_links_get_no_owner(outerdir, link_type):
    """test_chown_links_on_extract: untar does not restore owners, of links or otherwise."""
    arc = ArchiveMaker()
    arc.add("test.txt", content="x", mode=0o755)
    arc.add_raw("link", link_type, "test.txt")
    assert extract(arc, outerdir) is None
    for name in ("test.txt", "link"):
        assert os.lstat(outerdir / "dest" / name).st_uid == os.geteuid()


@needs_symlinks
def test_modes(outerdir):
    """test_modes: set-user-ID, set-group-ID and sticky bits are not restored."""
    arc = ArchiveMaker()
    arc.add("all_bits", mode=0o7777)
    arc.add("perm_bits", mode=0o777)
    arc.add("exec_group_other", mode=0o7676)
    arc.add("read_group_only", mode=0o0740)
    arc.add("no_bits", mode=0o0000)
    arc.add("dir/", mode=0o7777)
    assert extract(arc, outerdir) is None
    dest = outerdir / "dest"
    modes = {p.name: stat.S_IMODE(p.stat().st_mode) for p in dest.iterdir()}
    assert modes == {
        "all_bits": 0o755,
        "perm_bits": 0o755,
        "exec_group_other": 0o644,
        "read_group_only": 0o755,
        "no_bits": 0o644,
        "dir": 0o755,
    }


@needs_symlinks
def test_special_files(outerdir):
    arc = ArchiveMaker()
    arc.add("fifo", type=tarfile.FIFOTYPE)
    rejected(extract(arc, outerdir), match="unsupported type")
