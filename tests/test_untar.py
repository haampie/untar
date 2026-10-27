import collections
import errno
import gzip
import importlib.util
import io
import os
import random
import shutil
import stat
import subprocess
import sys
import tarfile

import pytest

import untar

FORMATS = [tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT, tarfile.PAX_FORMAT]
needs_symlinks = pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")


def make_tar(members, format=tarfile.PAX_FORMAT, compress=False) -> bytes:
    """Build an archive from (name, kind, payload, mode) members, kind being one of 'd', 'f',
    's' (payload is the target) and 'h' (payload is the member it links to)."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=format) as tar:
        for name, kind, payload, mode in members:
            info = tarfile.TarInfo(name)
            info.mode = mode
            info.type = {
                "d": tarfile.DIRTYPE,
                "f": tarfile.REGTYPE,
                "s": tarfile.SYMTYPE,
            }.get(kind, tarfile.LNKTYPE)
            if kind == "f":
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
            else:
                info.linkname = payload or ""
                tar.addfile(info)
    data = out.getvalue()
    return gzip.compress(data) if compress else data


def rejects(archive: bytes, tmp_path, match=None):
    """Extracting the archive fails, and leaves the destination empty."""
    with pytest.raises(untar.Error, match=match):
        untar.extract(io.BytesIO(archive), str(tmp_path / "dest"))
    assert os.listdir(tmp_path / "dest") == []


def snapshot(root):
    """The tree below root: types, normalized modes, contents, link targets, hardlinks."""
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


def tarfile_extract(data: bytes, dest) -> None:
    """The oracle: tarfile, trusting the archive."""
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        tar.extraction_filter = lambda member, path: member
        tar.extractall(dest)


SAMPLE = [
    ("pkg", "d", None, 0o755),
    ("pkg/bin", "d", None, 0o755),
    ("pkg/bin/app", "f", b"#!/bin/sh\n", 0o755),
    ("pkg/bin/link", "s", "app", 0o777),
    ("pkg/bin/abs", "s", "/usr/bin/env", 0o777),
    ("pkg/lib", "d", None, 0o755),
    ("pkg/lib/libfoo.so.1", "f", os.urandom(200_000), 0o644),
    ("pkg/lib/libfoo.so", "s", "libfoo.so.1", 0o777),
    ("pkg/lib/libfoo.a", "h", "pkg/lib/libfoo.so.1", 0o644),
    ("pkg/share/empty", "f", b"", 0o600),
    ("pkg/" + "x" * 150 + "/" + "y" * 120, "f", b"long name", 0o644),
    ("pkg/ünïcødé", "f", b"utf-8", 0o644),
]


@needs_symlinks
@pytest.mark.parametrize("format", FORMATS)
@pytest.mark.parametrize("compress", [False, True])
def test_same_tree_as_tarfile(tmp_path, format, compress):
    members = (
        SAMPLE
        if format != tarfile.USTAR_FORMAT
        else [m for m in SAMPLE if "x" * 150 not in m[0]]
    )
    data = make_tar(members, format, compress)
    tarfile_extract(data, tmp_path / "expected")
    assert untar.extract(io.BytesIO(data), str(tmp_path / "actual")) == ""
    assert snapshot(tmp_path / "actual") == snapshot(tmp_path / "expected")


@needs_symlinks
@pytest.mark.skipif(shutil.which("tar") is None, reason="needs tar")
@pytest.mark.parametrize("format", ["gnu", "posix", "ustar", "v7", "oldgnu"])
def test_archives_from_tar(tmp_path, format):
    src = tmp_path / "src"
    for name, kind, payload, mode in SAMPLE:
        if format in ("ustar", "v7") and len(name) > 99:
            continue
        path = src / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if kind == "d":
            path.mkdir(exist_ok=True)
        elif kind == "f":
            path.write_bytes(payload)
            path.chmod(mode)
        elif kind == "s":
            path.symlink_to(payload)
        else:
            os.link(src / payload, path)
    archive = tmp_path / "a.tar"
    result = subprocess.run(
        ["tar", f"--format={format}", "-cf", str(archive), "-C", str(src), "pkg"],
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"tar cannot write {format}: {result.stderr.decode()}")
    data = archive.read_bytes()
    tarfile_extract(data, tmp_path / "expected")
    untar.extract(str(archive), str(tmp_path / "actual"))
    assert snapshot(tmp_path / "actual") == snapshot(tmp_path / "expected")


def package_like(prefix, top_files=False, bundle=False, parents=True):
    """Members of a package archive: the parents of its prefix, then depth-first with files before dirs, and a manifest last."""
    parts = prefix.split("/")
    members = (
        [("/".join(parts[:i]), "d", None, 0o755) for i in range(1, len(parts))]
        if parents
        else []
    )
    members.append((prefix, "d", None, 0o755))
    if top_files:
        members.append((f"{prefix}/README", "f", b"readme", 0o644))
    members += [
        (f"{prefix}/.meta", "d", None, 0o755),
        (f"{prefix}/.meta/spec.json", "f", b"{}", 0o644),
    ]
    if not bundle:
        members += [
            (f"{prefix}/bin", "d", None, 0o755),
            (f"{prefix}/bin/app", "f", b"app", 0o755),
            (f"{prefix}/lib", "d", None, 0o755),
            (f"{prefix}/lib/libfoo.so", "f", b"foo", 0o644),
        ]
    members.append((f"{prefix}/.meta/manifest", "f", b"{}", 0o644))
    return members


def deep(base: str, length: int) -> str:
    while len(base) < length:
        base += "/" + "x" * 100
    return base


@pytest.mark.parametrize("top_files", [False, True])
@pytest.mark.parametrize("bundle", [False, True])
@pytest.mark.parametrize("parents", [False, True])
def test_root_marker(tmp_path, top_files, bundle, parents):
    prefix = "opt/store/linux/pkg-1.0-abcdef"
    data = make_tar(package_like(prefix, top_files, bundle, parents))
    assert untar.extract(io.BytesIO(data), str(tmp_path), root_marker=".meta") == prefix
    expected = (
        {".meta"}
        | ({"README"} if top_files else set())
        | (set() if bundle else {"bin", "lib"})
    )
    assert set(os.listdir(tmp_path)) == expected
    assert (tmp_path / ".meta" / "manifest").read_bytes() == b"{}"


def test_root_marker_long_paths(tmp_path):
    """Neither the archive's names nor the destination path limit each other."""
    path_max = (
        os.pathconf(str(tmp_path), "PC_PATH_MAX") if hasattr(os, "pathconf") else 260
    )
    prefix = deep("opt", int(path_max * 0.9)) + "/pkg"
    dest = deep(str(tmp_path), int(path_max * 0.7))
    os.makedirs(dest)
    data = make_tar(package_like(prefix), compress=True)
    assert untar.extract(io.BytesIO(data), dest, root_marker=".meta") == prefix
    assert sorted(os.listdir(dest)) == [".meta", "bin", "lib"]


def test_root_marker_shallowest(tmp_path):
    """A nested marker earlier in the archive does not decide the root."""
    members = [
        ("a", "d", None, 0o755),
        ("a/+early", "d", None, 0o755),
        ("a/+early/.meta", "d", None, 0o755),
        ("a/.meta", "d", None, 0o755),
        ("a/.meta/x", "f", b"x", 0o644),
    ]
    assert (
        untar.extract(io.BytesIO(make_tar(members)), str(tmp_path), root_marker=".meta")
        == "a"
    )
    assert sorted(os.listdir(tmp_path)) == ["+early", ".meta"]
    assert os.listdir(tmp_path / "+early") == [".meta"]


@pytest.mark.parametrize(
    "members,error",
    [
        ([("a/.meta", "d", None, 0o755), ("b/file", "f", b"", 0o644)], "outside of a"),
        ([("a/file", "f", b"", 0o644)], "no member named .meta"),
        ([("a/.meta", "d", None, 0o755), ("a", "f", b"", 0o644)], "non-directory"),
    ],
)
def test_root_marker_invalid(tmp_path, members, error):
    with pytest.raises(untar.Error, match=error):
        untar.extract(io.BytesIO(make_tar(members)), str(tmp_path), root_marker=".meta")
    assert os.listdir(tmp_path) == []


def test_member_order_does_not_matter(tmp_path):
    members = package_like("opt/store/pkg", top_files=True)
    for seed in range(50):
        rng = random.Random(seed)
        shuffled = members[:]
        rng.shuffle(shuffled)
        dest = tmp_path / str(seed)
        assert (
            untar.extract(
                io.BytesIO(make_tar(shuffled)), str(dest), root_marker=".meta"
            )
            == "opt/store/pkg"
        )
        assert sorted(os.listdir(dest)) == [".meta", "README", "bin", "lib"]


# Security


@pytest.mark.parametrize(
    "name", ["/etc/passwd", "../passwd", "a/../../passwd", "a/../../../passwd"]
)
def test_unsafe_names(tmp_path, name):
    """N12, N16: absolute names, and names with .."""
    dest = tmp_path / "dest"
    with pytest.raises(untar.Error, match="unsafe path"):
        untar.extract(io.BytesIO(make_tar([(name, "f", b"x", 0o644)])), str(dest))
    assert os.listdir(tmp_path) == ["dest"] and os.listdir(dest) == []


@pytest.mark.parametrize("name", ["...", "d/...", "d/....", "d/..x", "d/x.."])
def test_names_of_dots(tmp_path, name):
    """Only . and .. are special: see N05 for ."""
    untar.extract(io.BytesIO(make_tar([(name, "f", b"x", 0o644)])), str(tmp_path))
    path = str(tmp_path / name)
    if sys.platform == "win32":
        # Like untar, by extended-length path: other paths drop trailing dots on Windows
        path = "\\\\?\\" + path
    with open(path, "rb") as f:
        assert f.read() == b"x"


@needs_symlinks
@pytest.mark.parametrize("target", ["/tmp", "..", "sub"])
def test_no_writes_through_symlinks(tmp_path, target):
    """S11: a member below a symlink is not written through it, wherever it points."""
    dest = tmp_path / "dest"
    members = [
        ("sub", "d", None, 0o755),
        ("link", "s", target, 0o777),
        ("link/file", "f", b"x", 0o644),
    ]
    with pytest.raises(untar.Error, match="not a directory"):
        untar.extract(io.BytesIO(make_tar(members)), str(dest))
    assert os.listdir(tmp_path) == ["dest"] and os.listdir(dest) == []


@needs_symlinks
def test_no_writes_through_hardlinked_symlink(tmp_path):
    """S06: a hardlink to a symlink pointing outside is refused, and nothing writes into
    it."""
    outside = tmp_path / "outside"
    outside.write_text("original")
    members = [
        ("link", "s", str(outside), 0o777),
        ("hard", "h", "link", 0o777),
        ("hard", "f", b"overwritten", 0o644),
    ]
    with pytest.raises(untar.Error, match="which is a symlink"):
        untar.extract(io.BytesIO(make_tar(members)), str(tmp_path / "dest"))
    assert outside.read_text() == "original"


@needs_symlinks
def test_no_hardlinks_through_symlinks(tmp_path):
    """A hardlink target behind a symlinked dir is refused, and nothing outside is linked."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("secret")
    members = [("dir", "s", str(outside), 0o777), ("hard", "h", "dir/secret", 0o644)]
    with pytest.raises(untar.Error, match="not extracted"):
        untar.extract(io.BytesIO(make_tar(members)), str(tmp_path / "dest"))
    assert (outside / "secret").stat().st_nlink == 1


#: An entry of each kind: a file, a dir, a symlink, and a hardlink to a member named target
PAYLOADS = {"f": b"x", "d": None, "s": "/", "h": "target"}


@needs_symlinks
@pytest.mark.parametrize("kind", PAYLOADS)
def test_no_entries_through_symlinks(tmp_path, kind):
    """Not only files: no dir, symlink or hardlink is created through a symlink either."""
    outside = tmp_path / "outside"
    outside.mkdir()
    members = [
        ("target", "f", b"x", 0o644),
        ("link", "s", str(outside), 0o777),
        ("link/entry", kind, PAYLOADS[kind], 0o755),
    ]
    with pytest.raises(untar.Error, match="not a directory"):
        untar.extract(io.BytesIO(make_tar(members)), str(tmp_path / "dest"))
    assert os.listdir(outside) == []


@needs_symlinks
def test_no_writes_over_symlinks(tmp_path):
    """S10: a file after a symlink of the same name does not write through it."""
    outside = tmp_path / "outside"
    outside.write_text("original")
    members = [("f", "s", str(outside), 0o777), ("f", "f", b"overwritten", 0o644)]
    with pytest.raises(FileExistsError):
        untar.extract(io.BytesIO(make_tar(members)), str(tmp_path / "dest"))
    assert outside.read_text() == "original"


@needs_symlinks
def test_symlink_in_dest(tmp_path):
    """A symlink already in dest is not followed by members of that name."""
    (tmp_path / "outside").mkdir()
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "lib").symlink_to(tmp_path / "outside")
    members = [("lib", "d", None, 0o755), ("lib/owned", "f", b"x", 0o644)]
    with pytest.raises(untar.Error, match="exists in the destination"):
        untar.extract(io.BytesIO(make_tar(members)), str(dest))
    assert os.listdir(tmp_path / "outside") == []


def folds(path, a: str, b: str) -> bool:
    """Whether the filesystem of path treats names a and b as the same."""
    (path / a).write_text("")
    try:
        return (path / b).exists()
    finally:
        (path / a).unlink()


@needs_symlinks
@pytest.mark.parametrize(
    "link,name",
    [("A", "a"), ("\u00e9", "e\u0301"), ("\u017f", "s"), ("\u212a", "k")],
    ids=["case", "normalization", "long s", "kelvin"],
)
@pytest.mark.parametrize("kind", ["f", "d", "s", "h", "target"])
def test_names_that_fold(tmp_path, link, name, kind):
    """On filesystems that ignore case or normalize Unicode, like those of macOS and
    Windows, another name may lead through a symlink: in tar-minefield, a failure specific to
    a platform rather than an ambiguity. Neither entries below it nor
    hardlink targets go through it."""
    if not folds(tmp_path, link, name):
        pytest.skip(f"the filesystem tells {link!r} and {name!r} apart")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("secret")
    members = [("target", "f", b"x", 0o644), (link, "s", str(outside), 0o777)]
    if kind == "target":
        members.append(("hard", "h", f"{name}/secret", 0o644))
    else:
        members.append((f"{name}/entry", kind, PAYLOADS[kind], 0o755))
    with pytest.raises(untar.Error, match="not a directory|not extracted"):
        untar.extract(io.BytesIO(make_tar(members)), str(tmp_path / "dest"))
    assert os.listdir(outside) == ["secret"]
    assert (outside / "secret").stat().st_nlink == 1


class FdCounter:
    """Tracks the file descriptors that os.open opens and os.close closes."""

    def __init__(self, monkeypatch):
        self.open = set()
        self.opens = 0
        self.peak = 0
        self.real_open, self.real_close = os.open, os.close
        monkeypatch.setattr(os, "open", self._open)
        monkeypatch.setattr(os, "close", self._close)

    def _open(self, *args, **kwargs):
        fd = self.real_open(*args, **kwargs)
        self.open.add(fd)
        self.opens += 1
        self.peak = max(self.peak, len(self.open))
        return fd

    def _close(self, fd):
        self.open.discard(fd)
        self.real_close(fd)


@pytest.mark.skipif(not untar._DIR_FD, reason="needs dir file descriptors")
def test_hardlinks_reuse_open_dirs(tmp_path, monkeypatch):
    """A hardlink only opens the dirs of its target that are not open already."""
    fds = FdCounter(monkeypatch)
    deep = "/".join("abcdefgh")
    files = [(f"{deep}/x/f{i}", "f", b"", 0o644) for i in range(10)]
    links = [(f"{deep}/x/h{i}", "h", f"{deep}/x/f{i}", 0o644) for i in range(10)] + [
        (f"{deep}/y/h{i}", "h", f"{deep}/x/f{i}", 0o644) for i in range(10)
    ]
    untar.extract(io.BytesIO(make_tar(files)), str(tmp_path / "files"))
    without_links = fds.opens
    fds.opens = 0
    untar.extract(io.BytesIO(make_tar(files + links)), str(tmp_path / "links"))
    # Links in x open nothing, links in y open x, and y is opened once made
    assert fds.opens - without_links == 10 + 1


@pytest.mark.skipif(not untar._DIR_FD, reason="needs dir file descriptors")
def test_open_dirs_are_bounded(tmp_path, monkeypatch):
    """Only the deepest dirs on the stack stay open, and shallower ones are reopened."""
    monkeypatch.setattr(untar, "_MAX_OPEN_DIRS", 3)
    deep = "/".join("abcdefghij")
    members = [
        (f"{deep}/x/f", "f", b"f", 0o644),
        ("a/b/g", "f", b"g", 0o644),  # above the open dirs
        (f"{deep}/x/h", "h", f"{deep}/x/f", 0o644),
        (f"{deep}/y", "d", None, 0o755),
        ("a/b/c/l", "s", "d/e", 0o777),
        (f"{deep}/y/h", "h", "a/b/g", 0o644),
        ("a/b/c/d/e/z", "f", b"z", 0o644),
    ]
    fds = FdCounter(monkeypatch)
    untar.extract(io.BytesIO(make_tar(members)), str(tmp_path / "actual"))
    monkeypatch.undo()
    tarfile_extract(make_tar(members), tmp_path / "expected")
    assert snapshot(tmp_path / "actual") == snapshot(tmp_path / "expected")
    # dest, tmp, the open dirs, and a dir or file being opened from the last of them
    assert fds.peak <= 2 + 3 + 2
    assert not fds.open


@pytest.mark.skipif(not untar._DIR_FD, reason="needs dir file descriptors")
@pytest.mark.parametrize("max_open_dirs", [3, 64])
@pytest.mark.parametrize("valid", [True, False])
def test_tmp_is_removed(tmp_path, monkeypatch, valid, max_open_dirs):
    """tmp is removed, also below a prefix deeper than the open dirs. After a successful
    extraction whose dirs leading up to the root are all open, only rmdirs are needed."""
    monkeypatch.setattr(untar, "_MAX_OPEN_DIRS", max_open_dirs)
    prefix = "/".join("abcdefghijkl")
    members = [
        (f"{prefix}/.spack", "d", None, 0o755),
        (f"{prefix}/x/y/f", "f", b"f", 0o644),
        (f"{prefix}/x/y/l", "s", "/", 0o777),
    ]
    if not valid:
        members.append(("../escape", "f", b"", 0o644))
    dest = tmp_path / "dest"
    walks = []
    remove_tmp = untar._Extractor._remove_tmp
    monkeypatch.setattr(
        untar._Extractor,
        "_remove_tmp",
        lambda self: walks.append(1) or remove_tmp(self),
    )
    fds = FdCounter(monkeypatch)
    if valid:
        root = untar.extract(
            io.BytesIO(make_tar(members)), str(dest), root_marker=".spack"
        )
        assert root == prefix
    else:
        with pytest.raises(untar.Error, match="unsafe path"):
            untar.extract(
                io.BytesIO(make_tar(members)), str(dest), root_marker=".spack"
            )
    assert sorted(os.listdir(dest)) == ([".spack", "x"] if valid else [])
    assert len(walks) == (0 if valid and max_open_dirs > 12 else 1)
    # dest, tmp, the open dirs, and a dir or file being opened from the last of them
    assert fds.peak <= 2 + min(max_open_dirs, 14) + 2
    assert not fds.open


@pytest.mark.skipif(not untar._DIR_FD, reason="needs dir file descriptors")
def test_deep_tmp_is_removed_in_linear_time(tmp_path, monkeypatch):
    """Removing tmp opens each dir once, also far below the open dirs."""
    monkeypatch.setattr(untar, "_MAX_OPEN_DIRS", 3)
    depth = 1000
    members = [("d/" * depth + "f", "f", b"", 0o644), ("../escape", "f", b"", 0o644)]
    fds = FdCounter(monkeypatch)
    with pytest.raises(untar.Error, match="unsafe path"):
        untar.extract(io.BytesIO(make_tar(members)), str(tmp_path / "dest"))
    assert os.listdir(tmp_path / "dest") == []
    # Extraction opens each dir once, and so does removal
    assert fds.opens < 2 * depth + 10


def test_depth_is_limited(tmp_path, monkeypatch):
    """On macOS, creating an entry takes time linear in its depth: a tiny compressed archive
    of a single deep path would take hours."""
    monkeypatch.setattr(untar, "_MAX_DEPTH", 8)
    deepest = "/".join("abcdefgh")
    members = [(deepest, "f", b"x", 0o644), ("h", "h", deepest, 0o644)]
    untar.extract(io.BytesIO(make_tar(members)), str(tmp_path / "ok"))
    for members in [
        [(deepest + "/i", "f", b"x", 0o644)],
        [("f", "f", b"x", 0o644), ("h", "h", "./" + deepest + "/i", 0o644)],
    ]:
        with pytest.raises(untar.Error, match="more than 8 levels deep"):
            untar.extract(io.BytesIO(make_tar(members)), str(tmp_path / "deep"))
        assert os.listdir(tmp_path / "deep") == []


@pytest.mark.skipif(not untar._DIR_FD, reason="needs dir file descriptors")
def test_dest_dir_fd(tmp_path):
    """dest can be an open dir, which is extracted into wherever it moved, and stays open."""
    (tmp_path / "a").mkdir()
    fd = os.open(str(tmp_path / "a"), os.O_RDONLY)
    try:
        (tmp_path / "a").rename(tmp_path / "b")
        untar.extract(io.BytesIO(make_tar(SAMPLE)), fd)
        os.fstat(fd)
    finally:
        os.close(fd)
    tarfile_extract(make_tar(SAMPLE), tmp_path / "expected")
    assert snapshot(tmp_path / "b") == snapshot(tmp_path / "expected")


@needs_symlinks
def test_dest_symlink(tmp_path):
    """dest may be a symlink to a dir: the caller chose it, unlike symlinks in the archive."""
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to("real")
    untar.extract(io.BytesIO(make_tar(SAMPLE)), str(tmp_path / "link"))
    tarfile_extract(make_tar(SAMPLE), tmp_path / "expected")
    assert (tmp_path / "link").is_symlink()
    assert snapshot(tmp_path / "real") == snapshot(tmp_path / "expected")


@pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="POSIX")
def test_dir_fd_where_supported():
    """Otherwise the tests that need dir file descriptors are silently skipped."""
    assert untar._DIR_FD


@pytest.mark.parametrize(
    "supports",
    ["supports_dir_fd", "supports_follow_symlinks"],
)
def test_dir_fd_needs_every_call(monkeypatch, supports):
    """Without dir_fd or follow_symlinks support for a single call, entries are created by
    path, instead of failing with NotImplementedError halfway through an archive."""
    monkeypatch.setattr(os, supports, getattr(os, supports) - {os.stat})
    spec = importlib.util.spec_from_file_location("untar_copy", untar.__file__)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert not module._DIR_FD


def test_no_overwrites(tmp_path):
    """S07, S09: the same file twice."""
    members = [("file", "f", b"first", 0o644), ("file", "f", b"second", 0o644)]
    with pytest.raises(FileExistsError):
        untar.extract(io.BytesIO(make_tar(members)), str(tmp_path / "dest"))


LISTED_ONCE = [
    ("dir", "d", None, 0o755),
    ("dir/file", "f", b"x", 0o644),
    ("dir/symlink", "s", "file", 0o777),
    ("dir/dirlink", "s", ".", 0o777),
]


@needs_symlinks
def test_listed_twice(tmp_path):
    """S02: a dir listed twice is one dir."""
    data = make_tar(LISTED_ONCE + LISTED_ONCE[:1])
    untar.extract(io.BytesIO(data), str(tmp_path / "actual"))
    tarfile_extract(make_tar(LISTED_ONCE), tmp_path / "expected")
    assert snapshot(tmp_path / "actual") == snapshot(tmp_path / "expected")


@needs_symlinks
@pytest.mark.parametrize("again", LISTED_ONCE[1:], ids=lambda m: m[0])
def test_listed_twice_as_hardlinks(tmp_path, again):
    """S04: tar archives other entries listed twice as hardlinks to themselves, symlinks
    included, which implementations replace, empty, or leave alone."""
    name, _, _, mode = again
    rejects(make_tar(LISTED_ONCE + [(name, "h", name, mode)]), tmp_path, "to itself")


def is_gnu_tar() -> bool:
    if shutil.which("tar") is None:
        return False
    version = subprocess.run(["tar", "--version"], stdout=subprocess.PIPE, check=False)
    return b"GNU tar" in version.stdout


@needs_symlinks
@pytest.mark.skipif(
    not is_gnu_tar(), reason="bsdtar archives a symlink twice as a symlink"
)
@pytest.mark.parametrize("format", ["gnu", "posix"])
def test_listed_twice_by_tar(tmp_path, format):
    """S04: like GNU tar's link04 test, tar cf archive dir dir, which archives the entries
    of dir again as hardlinks to themselves."""
    src = tmp_path / "src"
    for name, kind, payload, _ in LISTED_ONCE:
        if kind == "d":
            (src / name).mkdir(parents=True)
        elif kind == "f":
            (src / name).write_bytes(payload)
        else:
            (src / name).symlink_to(payload)
    archive = tmp_path / "a.tar"
    subprocess.run(
        [
            "tar",
            f"--format={format}",
            "-cf",
            str(archive),
            "-C",
            str(src),
            "dir",
            "dir",
        ],
        check=True,
    )
    with pytest.raises(untar.Error, match="to itself"):
        untar.extract(str(archive), str(tmp_path / "actual"))


def test_dir_hardlinked_to_itself(tmp_path):
    members = [("dir", "d", None, 0o755), ("dir", "h", "dir", 0o755)]
    with pytest.raises(untar.Error, match="non-directory dir"):
        untar.extract(io.BytesIO(make_tar(members)), str(tmp_path))


@pytest.mark.parametrize("linkname", ["/etc/passwd", "../outside"])
def test_unsafe_hardlinks(tmp_path, linkname):
    with pytest.raises(untar.Error, match="unsafe path"):
        untar.extract(
            io.BytesIO(make_tar([("hard", "h", linkname, 0o644)])), str(tmp_path / "d")
        )


@pytest.mark.parametrize("type", [tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE])
def test_special_files(tmp_path, type):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        info = tarfile.TarInfo("dev")
        info.type = type
        tar.addfile(info)
    with pytest.raises(untar.Error, match="unsupported type"):
        untar.extract(io.BytesIO(out.getvalue()), str(tmp_path / "d"))


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_special_modes_are_not_restored(tmp_path):
    data = make_tar([("suid", "f", b"x", 0o4777), ("dir", "d", None, 0o3777)])
    untar.extract(io.BytesIO(data), str(tmp_path))
    assert stat.S_IMODE(os.stat(tmp_path / "suid").st_mode) == 0o755
    assert stat.S_IMODE(os.stat(tmp_path / "dir").st_mode) == 0o755


@needs_symlinks
def test_fuzz(tmp_path):
    """Corrupt archives fail with an error or extract something, but never write outside."""
    data = make_tar(SAMPLE, compress=False)
    rng = random.Random(0)
    outcomes = collections.Counter()
    for i in range(300):
        corrupt = bytearray(data)
        for _ in range(rng.randint(1, 8)):
            corrupt[rng.randrange(len(corrupt))] = rng.randrange(256)
        dest = tmp_path / "work" / str(i)
        try:
            untar.extract(io.BytesIO(bytes(corrupt)), str(dest))
            outcomes["ok"] += 1
        except (untar.Error, OSError, UnicodeError) as e:
            outcomes[type(e).__name__] += 1
        assert os.listdir(tmp_path) == ["work"]
        assert all(not name.startswith(".untar-") for name in os.listdir(dest))
    assert outcomes["Error"] > 0


# Streaming


class ReadOnly:
    """A stream that can only be read, like a pipe or an HTTP response."""

    def __init__(self, data: bytes, max_read: int = 1000) -> None:
        self.data = io.BytesIO(data)
        self.max_read = max_read

    def read(self, size=-1):
        return self.data.read(self.max_read if size < 0 else min(size, self.max_read))


@needs_symlinks
@pytest.mark.parametrize("compress", [False, True])
def test_unseekable_stream_with_short_reads(tmp_path, compress):
    data = make_tar(SAMPLE, compress=compress)
    untar.extract(ReadOnly(data), str(tmp_path / "actual"))
    tarfile_extract(make_tar(SAMPLE), tmp_path / "expected")
    assert snapshot(tmp_path / "actual") == snapshot(tmp_path / "expected")


def test_decompresses_once(tmp_path, monkeypatch):
    def rewind(self):
        raise AssertionError("gzip stream rewound")

    monkeypatch.setattr(gzip._GzipReader, "_rewind", rewind)
    path = tmp_path / "a.tar.gz"
    path.write_bytes(make_tar(SAMPLE[:7], compress=True))
    untar.extract(str(path), str(tmp_path / "dest"))


def test_reader():
    data = make_tar(
        [
            ("a", "d", None, 0o755),
            ("a/f", "f", b"hello" * 1000, 0o644),
            ("a/g", "f", b"skipped", 0o644),
        ]
    )
    reader = untar.TarReader(io.BytesIO(data))
    members = []
    for member in reader:
        members.append((member.name, member.isdir(), member.isreg()))
        if member.name == "a/f":
            assert b"".join(reader.chunks(7)) == b"hello" * 1000
    assert members == [("a", True, False), ("a/f", False, True), ("a/g", False, True)]


# Modes and groups


@pytest.fixture(params=[True, False], ids=["dir_fd", "path"])
def dir_fd(request, monkeypatch):
    """Extract relative to dir file descriptors, and by path like where they are not supported."""
    if request.param and not untar._DIR_FD:
        pytest.skip("no dir file descriptors")
    monkeypatch.setattr(untar, "_DIR_FD", request.param)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
@pytest.mark.parametrize("umask", [0o022, 0o077, 0o000])
@pytest.mark.parametrize(
    "file_mode,dir_mode", [(0o755, 0o755), (0o750, 0o2750), (0o700, 0o700)]
)
def test_modes(tmp_path, umask, file_mode, dir_mode, dir_fd):
    # New dirs get the group of their parent on macOS. chmod drops set-group-ID unless
    # the user is in that group, so give tmp_path one the user is in.
    os.chown(tmp_path, -1, os.getegid())
    old = os.umask(umask)
    try:
        untar.extract(
            io.BytesIO(make_tar(SAMPLE)),
            str(tmp_path),
            file_mode=file_mode,
            dir_mode=dir_mode,
        )
    finally:
        os.umask(old)
    for dirpath, dirnames, filenames in os.walk(tmp_path / "pkg"):
        for name in dirnames:
            assert (
                stat.S_IMODE(os.lstat(os.path.join(dirpath, name)).st_mode) == dir_mode
            )
        for name in filenames:
            s = os.lstat(os.path.join(dirpath, name))
            if stat.S_ISREG(s.st_mode):
                expected = file_mode if name == "app" else file_mode & ~0o111
                assert stat.S_IMODE(s.st_mode) == expected, name


@pytest.mark.parametrize("dir_mode", [0o555, 0o355, 0o655, 0o055])
def test_dir_mode_without_owner_rwx(tmp_path, dir_mode):
    """Entries are created in dirs after their mode is set, so the owner needs rwx."""
    with pytest.raises(ValueError, match="dir_mode"):
        untar.extract(
            io.BytesIO(make_tar(SAMPLE)), str(tmp_path / "d"), dir_mode=dir_mode
        )
    assert not (tmp_path / "d").exists()


@pytest.mark.skipif(
    not hasattr(os, "getgroups") or len(os.getgroups()) < 2, reason="needs 2 groups"
)
def test_gid(tmp_path, dir_fd):
    gid = next(g for g in os.getgroups() if g != os.getegid())
    untar.extract(io.BytesIO(make_tar(SAMPLE)), str(tmp_path), gid=gid, dir_mode=0o2755)
    for dirpath, dirnames, filenames in os.walk(tmp_path / "pkg"):
        for name in dirnames + filenames:
            assert os.lstat(os.path.join(dirpath, name)).st_gid == gid, name


# Where links are not supported


def fail_with_eperm(*args, **kwargs):
    raise OSError(errno.EPERM, "links are not supported")


@pytest.mark.parametrize("target_first", [False, True])
def test_links_are_copied_where_unsupported(tmp_path, monkeypatch, target_first):
    monkeypatch.setattr(os, "symlink", fail_with_eperm)
    monkeypatch.setattr(os, "link", fail_with_eperm)
    target = [("lib/libfoo.so.1", "f", b"foo", 0o644)]
    links = [
        ("lib/libfoo.so", "s", "libfoo.so.1", 0o777),
        ("lib/sub", "s", "../lib", 0o777),
    ]
    members = [("lib", "d", None, 0o755)] + (
        target + links if target_first else links + target
    )
    members.append(("lib/libfoo.a", "h", "lib/libfoo.so.1", 0o644))
    untar.extract(io.BytesIO(make_tar(members)), str(tmp_path))
    for name in ("libfoo.so", "libfoo.so.1", "libfoo.a"):
        path = tmp_path / "lib" / name
        assert not path.is_symlink() and path.read_bytes() == b"foo"
    assert (tmp_path / "lib" / "sub").is_dir()


@pytest.mark.parametrize("target", ["/abs", "../up", "missing", "s"])
def test_symlinks_that_cannot_be_copied(tmp_path, monkeypatch, target):
    """N07: rather than drop a symlink, which would leave its path to other members, refuse
    it."""
    monkeypatch.setattr(os, "symlink", fail_with_eperm)
    members = [("f", "f", b"x", 0o644), ("s", "s", target, 0o777)]
    rejects(make_tar(members), tmp_path, "symlink s to")


@pytest.mark.parametrize(
    "entry",
    [("s", "f", b"y", 0o644), ("s/x", "f", b"y", 0o644), ("s", "d", None, 0o755)],
)
@pytest.mark.parametrize("target", ["dir", "later"])
def test_no_entries_at_or_below_copied_symlinks(tmp_path, monkeypatch, entry, target):
    """S10, S11: nothing is created over or through a symlink, nor over or through its
    copy, whether it is copied right away or after the last member."""
    monkeypatch.setattr(os, "symlink", fail_with_eperm)
    members = [("dir", "d", None, 0o755), ("s", "s", target, 0o777), entry]
    rejects(make_tar(members), tmp_path, "at or below the symlink s")


@pytest.mark.parametrize("target_first", [False, True])
def test_no_hardlinks_to_copied_symlinks(tmp_path, monkeypatch, target_first):
    """S06: nor to a copy of a symlink."""
    monkeypatch.setattr(os, "symlink", fail_with_eperm)
    target = [("f", "f", b"x", 0o644)]
    members = [("s", "s", "f", 0o777), ("h", "h", "s", 0o644)]
    members = target + members if target_first else members[:1] + target + members[1:]
    rejects(make_tar(members), tmp_path, "which is a symlink")


def test_symlink_chains_are_copied_where_unsupported(tmp_path, monkeypatch):
    """A symlink to a symlink is copied after it, also where it comes first, as in sorted
    shared library chains. Links are copied in time linear in their number."""
    monkeypatch.setattr(os, "symlink", fail_with_eperm)
    copies = []
    copy = untar._Extractor._copy
    monkeypatch.setattr(
        untar._Extractor,
        "_copy",
        lambda self, *args: copies.append(1) or copy(self, *args),
    )
    n = 100
    members = [(f"l{i}", "s", f"l{i + 1}", 0o777) for i in range(n)]
    members.append((f"l{n}", "f", b"foo", 0o644))
    untar.extract(io.BytesIO(make_tar(members)), str(tmp_path))
    for i in range(n + 1):
        assert (tmp_path / f"l{i}").read_bytes() == b"foo"
    assert len(copies) <= 2 * n


def test_solaris_extended_header(tmp_path):
    """Solaris tar writes pax headers with type X instead of x."""
    data = bytearray(make_tar([("x" * 120, "f", b"long", 0o644)], tarfile.PAX_FORMAT))
    assert data[156:157] == tarfile.XHDTYPE
    data[156:157] = b"X"
    data[148:156] = b"%06o\0 " % (sum(data[:148]) + sum(data[156:512]) + 256)
    untar.extract(io.BytesIO(bytes(data)), str(tmp_path))
    assert (tmp_path / ("x" * 120)).read_bytes() == b"long"


@needs_symlinks
@pytest.mark.parametrize(
    "members",
    [
        [("link", "s", ".", 0o777), ("link", "s", "..", 0o777)],
        [("link", "s", ".", 0o777), ("link", "d", None, 0o755)],
        [("file", "f", b"", 0o644), ("file", "d", None, 0o755)],
    ],
)
def test_no_entries_over_others(tmp_path, members):
    """S08: one path as members of different kinds."""
    with pytest.raises((FileExistsError, untar.Error)):
        untar.extract(io.BytesIO(make_tar(members)), str(tmp_path))
