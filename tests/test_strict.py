"""Ambiguities: archives from which tar implementations extract different trees, which untar
rejects, or reads in one way only.

Grouped by the categories of tar-minefield: framing (F), names (N), kinds (K), and order and
state (S). A docstring that starts with an identifier, such as F12, names the cases of its test
suite that the test covers in more variants: test_minefield.py runs the cases themselves."""

import errno
import gzip
import io
import itertools
import os
import sys
import tarfile

import pytest
from test_untar import ReadOnly, make_tar, needs_symlinks

import untar

EOF = bytes(1024)


def header(name="f", type=b"0", size=b"", linkname="", magic=b"ustar\x0000", prefix=""):
    """A raw ustar header, with any size field and a correct checksum."""
    h = bytearray(512)
    h[0 : len(name.encode())] = name.encode()
    h[100:108] = b"0000644\0"
    h[124:136] = size.ljust(12, b"\0") if isinstance(size, bytes) else b"%011o\0" % size
    h[156:157] = type
    h[157 : 157 + len(linkname.encode())] = linkname.encode()
    h[257:265] = magic
    h[345 : 345 + len(prefix.encode())] = prefix.encode()
    return checksum(h)


def checksum(h: bytearray, field=lambda total: b"%06o\0 " % total) -> bytes:
    """The header h with the checksum field(total) of its bytes."""
    h = bytearray(h)
    h[148:156] = b" " * 8
    h[148:156] = field(sum(h))
    return bytes(h)


def data(content: bytes) -> bytes:
    return content + bytes(-len(content) % 512)


def member(name="f", content=b"", **kwargs):
    return header(name, size=len(content), **kwargs) + data(content)


def extended(type, content: bytes) -> bytes:
    return header(
        "././@LongLink" if type in b"LK" else "pax", type, len(content)
    ) + data(content)


def record(key, value) -> bytes:
    body = (
        b" "
        + key.encode()
        + b"="
        + (value if isinstance(value, bytes) else value.encode())
    )
    body += b"\n"
    n = len(body) + 1
    while len(b"%d" % n) + len(body) != n:
        n += 1
    return b"%d" % n + body


def members(archive: bytes, limit=100):
    reader = untar.TarReader(io.BytesIO(archive))
    return [(m.name, m.linkname, m.size) for m in itertools.islice(reader, limit)]


def rejects(archive: bytes, tmp_path, match=None):
    with pytest.raises(untar.Error, match=match):
        untar.extract(io.BytesIO(archive), str(tmp_path / "dest"))
    assert os.listdir(tmp_path / "dest") == []


def test_tarfile_reads_our_headers():
    """The raw headers here are valid: tarfile agrees on the members of a simple archive."""
    archive = member("a", b"x") + member("d/", type=b"5") + EOF
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        assert [(m.name, m.size) for m in tar] == [("a", 1), ("d", 0)]


# Framing (F): where the data of a member ends and the next header begins, and which headers
# belong to a member.

# Numbers: octal and pax decimal, in ASCII digits only.


@pytest.mark.parametrize(
    "size", [b"-1777", b"+17", b"0o17", b"0_17", b"1 7", b"\xd9\xa3"]
)
def test_invalid_octal_numbers(tmp_path, size):
    """F12: a sign, a prefix, an underscore, a space between digits, digits other than
    ASCII."""
    archive = header(size=size) + member("secret", b"hello") + EOF
    with pytest.raises(untar.Error, match="invalid number"):
        members(archive)
    rejects(archive, tmp_path, "invalid number")


@pytest.mark.parametrize(
    "size",
    [
        b"\x0000000002000",
        b" \x000000002000",
        b"\n0000002000",
        b"\t0000002000",
        b"\x0b0000002000",
        b"1\x00777",
        b"2000\x00X",
    ],
)
def test_octal_numbers_with_odd_padding(size):
    """Implementations disagree on the size of a member, and so on where the next header
    is: some skip a leading NUL or whitespace other than spaces, others stop there, and some
    read the digits after a NUL."""
    with pytest.raises(untar.Error, match="invalid number"):
        members(header(size=size) + member("hidden", bytes(1024)) + EOF)


@pytest.mark.parametrize(
    "size", ["", "abc", "-1536", "1_0", "+3", " 3", "٣", "0x3", "3.0"]
)
def test_invalid_pax_sizes(tmp_path, size):
    """F21 to F25: an empty pax size, a sign, a leading space, digits other than ASCII."""
    archive = extended(b"x", record("size", size)) + member("f", b"abc") + EOF
    rejects(archive, tmp_path, "invalid pax size")


@pytest.mark.parametrize(
    "records",
    [
        record("size", "0" * 5000 + "3"),
        b"1" * 5000 + b" path=x\n",
    ],
    ids=["size", "length"],
)
def test_pax_numbers_with_many_digits(tmp_path, records):
    """int() takes time quadratic in the number of digits, and from Python 3.11 on refuses
    more than 4300 of them with a ValueError."""
    rejects(
        extended(b"x", records) + member("f", b"abc") + EOF, tmp_path, "invalid pax"
    )


@pytest.mark.parametrize("size", ["03", "00", "0" * 21 + "3"])
def test_pax_numbers_with_zero_padding(tmp_path, size):
    """F26: a leading zero, which some implementations take for octal."""
    archive = extended(b"x", record("size", size)) + member("f", b"abc") + EOF
    rejects(archive, tmp_path, "invalid pax size")


def test_valid_numbers():
    """F01: leading and trailing spaces and NULs, octal without terminator, and base-256."""
    for size in [
        b"  3",
        b"3 ",
        b"00000000003",
        b"3\0   ",
        b"3\0 \0 ",
        b"\x80" + (3).to_bytes(11, "big"),
    ]:
        assert members(header(size=size) + data(b"abc") + EOF) == [("f", "", 3)]


def test_negative_sizes():
    """F29: a negative size would move a reader back, maybe in circles."""
    size = b"\xff" * 11 + b" "
    with pytest.raises(untar.Error, match="negative"):
        members((header(size=size) + data(b"abc")) * 3 + EOF)


# Checksums


@pytest.mark.parametrize(
    "field",
    [
        lambda total: b"\x80" + total.to_bytes(7, "big"),
        lambda total: b"%06o\0X" % total,
        lambda total: b"\t%06o\0" % total,
    ],
    ids=["base-256", "garbage", "tab"],
)
def test_odd_checksums(field):
    """Implementations that refuse a checksum skip to the next block that is a valid header,
    which may be in the data of this member."""
    archive = checksum(header("f", size=1024), field) + member("hidden", bytes(1024))
    with pytest.raises(untar.Error, match="invalid number"):
        members(archive + EOF)


@pytest.mark.parametrize(
    "format", [b"%06o\0 ", b"%06o \0", b"%07o\0", b"%08o", b" %06o\0"]
)
def test_checksum_variants(format):
    """F32: space or NUL terminated, unterminated, and with leading spaces."""
    h = checksum(header("f", size=3), lambda total: format % total)
    assert members(h + data(b"abc") + EOF) == [("f", "", 3)]


def test_signed_checksum():
    """F06: the signed sum of the bytes, which some old tar implementations wrote, and
    others refuse."""
    h = bytearray(header("f", size=3))
    h[265:270] = b"\xe9" * 5
    signed = checksum(h, lambda total: b"%06o\0 " % (total - 256 * 5))
    with pytest.raises(untar.Error, match="checksum"):
        members(signed + data(b"abc") + EOF)


def test_invalid_checksum(tmp_path):
    data = bytearray(make_tar([("file", "f", b"x", 0o644)], tarfile.USTAR_FORMAT))
    data[0] ^= 1
    with pytest.raises(untar.Error, match="checksum"):
        untar.extract(io.BytesIO(bytes(data)), str(tmp_path))


# Pax records


@pytest.mark.parametrize(
    "records",
    [
        b"5 abc\n",
        b"6 =abc\n",
        b"+9 path=x\n",
        b"9path=x\n",
        b"30 path=x\n",
        b"0 path=x\n",
        # Leading zeros: some implementations find the end of a record from the length as
        # written
        b"011 path=x\n",
        # A NUL or blanks in a key: implementations stop there, skip the key, or skip the
        # blanks
        record("a\0b", "c") + record("size", "0"),
        record(" size", "0"),
        record("\tpath", "x"),
        # Records that do not fill the header: implementations stop at a NUL, or skip the
        # record
        record("path", "x") + b"\0",
        record("path", "x") + b"\0" + record("path", "y"),
    ],
)
def test_invalid_pax_records(tmp_path, records):
    """F36: a length that does not count the whole record, and others."""
    rejects(extended(b"x", records) + member() + EOF, tmp_path, "invalid pax")


@pytest.mark.parametrize("key", ["path", "comment", "mtime"])
def test_newlines_in_pax_values(tmp_path, key):
    """F13, F28: records are delimited by their length, but some implementations split them
    on newlines, and see another record."""
    archive = extended(b"x", record(key, "x\n12 size=512")) + member("f", b"abc") + EOF
    rejects(archive, tmp_path, "newline")


def test_newlines_in_xattrs(tmp_path):
    """Except in xattrs, which some archives have, and which are not extracted."""
    archive = (
        extended(b"x", record("SCHILY.xattr.user.k", "a\nb"))
        + member("f", b"abc")
        + EOF
    )
    untar.extract(io.BytesIO(archive), str(tmp_path))
    assert (tmp_path / "f").read_bytes() == b"abc"


# Global pax headers


@pytest.mark.parametrize("key", ["path", "linkpath", "size"])
def test_global_pax_names_and_sizes(tmp_path, key):
    """F20, N21: implementations disagree on whether global names and sizes apply to later
    members."""
    archive = extended(b"g", record(key, "0")) + member("a", bytes(1024)) + EOF
    rejects(archive, tmp_path, "global pax")


def test_global_pax_header_after_extended_header(tmp_path):
    """F19: the extended header applies to the global header for some implementations, and
    to the member for others."""
    archive = (
        extended(b"x", record("path", "a"))
        + extended(b"g", record("comment", "hi"))
        + member("f", b"x")
        + EOF
    )
    rejects(archive, tmp_path, "global pax header after")


def test_global_pax_other_keys(tmp_path):
    """F17: the comment that git archive writes."""
    archive = extended(b"g", record("comment", "hi")) + member("a", b"x") + EOF
    untar.extract(io.BytesIO(archive), str(tmp_path))
    assert (tmp_path / "a").read_bytes() == b"x"


# Sizes of members without data, and of pax headers


@pytest.mark.parametrize("type", [b"1", b"2", b"3", b"4", b"5", b"6"])
@pytest.mark.parametrize("pax", [False, True])
def test_size_without_data(type, pax):
    """F33, F34, F35: tar and tarfile read what follows a link, device or fifo with a size
    as headers, and skip the size of a dir; the Rust tar crates skip it as data, and some
    implementations take the size of a dir for data: either could miss a member."""
    hidden = member("hidden", b"x")
    linkname = "t" if type in b"12" else ""
    if pax:
        # Too large for the ustar size, which is 0 then
        size = untar._PAX_SIZE
        archive = extended(b"x", record("size", str(size))) + header(
            "f", type, 0, linkname
        )
    else:
        size = 512
        archive = header("f", type, size, linkname)
    with pytest.raises(untar.Error, match=f"with size {size}"):
        members(archive + hidden + EOF)


@pytest.mark.parametrize("pax_size,size", [(0, 1024), (1024, 0), (1024, 512)])
def test_pax_size_and_size(tmp_path, pax_size, size):
    """F14, F15: implementations without pax support, or that ignore its size, use the size
    in the header."""
    archive = (
        extended(b"x", record("size", str(pax_size)))
        + header("f", size=size)
        + member("hidden", bytes(1024))
        + EOF
    )
    rejects(archive, tmp_path, f"pax size {pax_size} and size {size}")


def test_pax_sizes_for_large_files():
    """Writers use a pax size for files too large for the size in the header, and write 0
    or the same size there."""
    large = untar._PAX_SIZE
    for size in [0, large]:
        archive = extended(b"x", record("size", str(large))) + header("f", size=size)
        reader = untar.TarReader(io.BytesIO(archive))
        assert next(iter(reader)).size == large
    archive = extended(b"x", record("size", "3")) + member("f", b"abc") + EOF
    assert members(archive) == [("f", "", 3)]


# Types


def test_unknown_types_have_data():
    """F16: like tarfile, the reader does not lose its place on a type it does not know, and
    extraction rejects it."""
    archive = (
        member("mystery", b"DATA" * 200, type=b"Z") + member("after", b"after") + EOF
    )
    assert [name for name, _, _ in members(archive)] == ["mystery", "after"]


@pytest.mark.parametrize(
    "key,value", [("SCHILY.realsize", "10000"), ("SUN.holesdata", " 0 512")]
)
def test_sparse_pax_keys(tmp_path, key, value):
    """Some implementations make a sparse file of these, with other contents."""
    archive = extended(b"x", record(key, value)) + member("f", b"A" * 1024) + EOF
    rejects(archive, tmp_path, "sparse")


def test_contiguous_files(tmp_path):
    """Type 7 has data for most implementations, but not for all."""
    archive = member("f", b"x" * 1024, type=b"7") + member("after", b"y") + EOF
    assert [name for name, _, _ in members(archive)] == ["f", "after"]
    rejects(archive, tmp_path, "unsupported type")


# Extended headers


@pytest.mark.parametrize("type", [b"x", b"L", b"K"])
@pytest.mark.parametrize("end", [b"", EOF])
def test_extended_header_without_member(tmp_path, type, end):
    """Dropping it silently would hide truncation."""
    content = record("path", "a") if type == b"x" else b"a\0"
    match = "ends after" if end else "truncated"
    rejects(member("first") + extended(type, content) + end, tmp_path, match)


def test_extended_headers_are_limited_per_member(tmp_path):
    big = "x" * (600 * 1024)
    archive = extended(b"L", big.encode() + b"\0") + extended(
        b"x", record("linkpath", big)
    )
    rejects(archive + member("f", type=b"1") + EOF, tmp_path, "more than 1 MiB")


def test_large_extended_header(tmp_path):
    data = make_tar([("x" * (2 * 1024 * 1024), "f", b"", 0o644)], tarfile.GNU_FORMAT)
    with pytest.raises(untar.Error, match="extended header"):
        untar.extract(io.BytesIO(data), str(tmp_path))


# The end of the archive


def test_truncated(tmp_path):
    """F08: an archive that ends in the data of a member."""
    data = make_tar([("file", "f", os.urandom(5000), 0o644)])
    with pytest.raises(untar.Error, match="truncated"):
        untar.extract(io.BytesIO(data[:2000]), str(tmp_path))


TWO_MEMBERS = make_tar(
    [("a", "f", b"a", 0o644), ("b", "f", b"b", 0o644)], tarfile.USTAR_FORMAT
)[: 4 * 512]


@pytest.mark.parametrize(
    "archive,error",
    [
        (TWO_MEMBERS, "truncated"),
        (TWO_MEMBERS[:1024], "truncated"),
        (TWO_MEMBERS + bytes(512), "truncated"),
        (
            TWO_MEMBERS[:1024] + bytes(512) + TWO_MEMBERS[1024:] + bytes(1024),
            "lone zero block",
        ),
        (b"", "empty"),
        (gzip.compress(b""), "empty"),
    ],
)
def test_end_of_archive_marker(tmp_path, archive, error):
    """F03, F04, F09: without two zero blocks at the end, truncation between members would
    go unnoticed."""
    with pytest.raises(untar.Error, match=error):
        untar.extract(io.BytesIO(archive), str(tmp_path / "d"))
    assert os.listdir(tmp_path / "d") == []
    untar.extract(io.BytesIO(TWO_MEMBERS + bytes(1024)), str(tmp_path / "d"))
    assert sorted(os.listdir(tmp_path / "d")) == ["a", "b"]


@pytest.mark.parametrize(
    "archive",
    [
        TWO_MEMBERS + bytes(1024) + TWO_MEMBERS + bytes(1024),
        TWO_MEMBERS + bytes(1024 + 2 * untar._BUF) + b"x",
        gzip.compress(TWO_MEMBERS + bytes(1024))
        + gzip.compress(TWO_MEMBERS + bytes(1024)),
    ],
    # Not the archives, which are too long for an environment variable on Windows
    ids=["two archives", "data after 2 MiB of zeros", "two gzip files"],
)
def test_data_after_end_of_archive_marker(tmp_path, archive):
    """F07, and F02, which untar rejects too: every implementation ignores it, so a second
    archive after the first would go unnoticed."""
    with pytest.raises(untar.Error, match="after the end-of-archive marker"):
        untar.extract(io.BytesIO(archive), str(tmp_path / "d"))
    assert os.listdir(tmp_path / "d") == []


@pytest.mark.parametrize("compress", [False, True])
def test_zeros_after_end_of_archive_marker(tmp_path, compress):
    """Writers pad archives with zeros, to a multiple of the record size for example."""
    archive = TWO_MEMBERS + bytes(1024 + 2 * untar._BUF + 7)
    untar.extract(
        ReadOnly(gzip.compress(archive) if compress else archive), str(tmp_path)
    )
    assert sorted(os.listdir(tmp_path)) == ["a", "b"]


# Names (N): which of several fields gives a member its name, and how it is normalized. One
# name per member: implementations resolve conflicts between them differently.


@pytest.mark.parametrize(
    "headers",
    [
        extended(b"x", record("path", "a")) + extended(b"x", record("path", "b")),
        extended(b"x", record("path", "a")) + extended(b"X", record("size", "1")),
        extended(b"L", b"a\0") + extended(b"L", b"b\0"),
        extended(b"K", b"a\0") + extended(b"K", b"b\0"),
    ],
)
def test_two_extended_headers_of_a_kind(tmp_path, headers):
    """N09: two pax headers, two GNU long names or two GNU long links for one member."""
    rejects(headers + member("f", type=b"2", linkname="t") + EOF, tmp_path, "two")


@pytest.mark.parametrize(
    "headers",
    [
        extended(b"x", record("path", "a")) + extended(b"L", b"b\0"),
        extended(b"L", b"b\0") + extended(b"x", record("path", "a")),
        extended(b"x", record("linkpath", "a")) + extended(b"K", b"b\0"),
        extended(b"L", b"b\0") + extended(b"x", record("mtime", "1")),
        extended(b"x", record("size", "0")) + extended(b"L", b"b\0"),
    ],
)
def test_pax_and_gnu_names(tmp_path, headers):
    """N08, N23, F10: a pax header and a GNU long name or link for one member, whatever the
    pax header has: each extends the next header, which may be the other."""
    rejects(headers + member("f", type=b"2", linkname="t") + EOF, tmp_path, "both")


@pytest.mark.parametrize(
    "key,value", [("path", ""), ("linkpath", ""), ("path", "a\0b")]
)
def test_invalid_pax_names(tmp_path, key, value):
    """N19, N22: a NUL inside a pax path, and an empty one, which POSIX says removes it."""
    archive = (
        extended(b"x", record(key, value)) + member("f", type=b"2", linkname="t") + EOF
    )
    rejects(archive, tmp_path, f"invalid pax {key}")


def test_pax_key_twice(tmp_path):
    """N20: implementations take the first or the last."""
    archive = extended(b"x", record("path", "a") + record("path", "b")) + member() + EOF
    rejects(archive, tmp_path, "twice")


@pytest.mark.parametrize("type", [b"L", b"K"])
def test_gnu_long_names_with_nul_inside(tmp_path, type):
    """Implementations that stop at the NUL and those that keep the rest see different
    names."""
    rejects(
        extended(type, b"good\0bad\0") + member("f", type=b"2", linkname="t") + EOF,
        tmp_path,
        "NUL inside",
    )


def test_gnu_long_names_end_with_nuls():
    archive = extended(b"L", b"name\0\0") + member("f", type=b"2", linkname="t") + EOF
    assert members(archive) == [("name", "t", 0)]


@pytest.mark.parametrize("type", [b"L", b"K"])
def test_empty_gnu_long_names(tmp_path, type):
    rejects(
        extended(type, b"\0") + member("f", type=b"2", linkname="t") + EOF,
        tmp_path,
        "empty",
    )


@pytest.mark.parametrize("version", [b"00", b"\0\0"])
def test_prefix_in_ustar_headers(version):
    """F05: the POSIX magic, with its version 00 or NULs as some Java archivers write it,
    has a name prefix."""
    archive = member("name", prefix="prefix", magic=b"ustar\0" + version) + EOF
    assert members(archive) == [("prefix/name", "", 0)]


@pytest.mark.parametrize(
    "magic", [b"ustar\0 \0", b"ustar\0  ", b"ustar\x0001", b"ustar 00", b"ustarX00"]
)
def test_other_magics(tmp_path, magic):
    """F11: another version of the POSIX magic, or a damaged magic, which implementations
    take for ustar, for v7, or not for a header: with a name prefix or not."""
    rejects(member("name", magic=magic) + EOF, tmp_path, "magic")


@pytest.mark.parametrize("magic", [b"ustar  \0", bytes(8)])
def test_prefix_in_other_headers(tmp_path, magic):
    """N11: GNU incremental archives have times there, which some implementations take for a
    prefix."""
    assert members(member("name", magic=magic) + EOF) == [("name", "", 0)]
    rejects(member("name", prefix="prefix", magic=magic) + EOF, tmp_path, "not ustar")


def test_star_prefix():
    """N10: star's prefix is 131 bytes, followed by times: some implementations read only
    those, others all 155."""
    star = bytearray(header("name", prefix="p" * 131))
    star[476:500] = b"14000000000\0" * 2
    star[508:512] = b"tar\0"
    with pytest.raises(untar.Error, match="star header"):
        members(checksum(star) + EOF)
    star[475] = 0
    assert members(checksum(star) + EOF) == [("p" * 130 + "/name", "", 0)]


def test_bytes_after_nul_in_names(tmp_path):
    """N14: a name ends at its first NUL, but some implementations keep what follows."""
    rejects(member("a\0b") + EOF, tmp_path, "after the NUL")
    # Unless a pax path or a GNU long name gives the name
    for headers in [extended(b"x", record("path", "long")), extended(b"L", b"long\0")]:
        assert members(headers + member("a\0b") + EOF) == [("long", "", 0)]


def test_names_that_are_not_utf8(tmp_path):
    """N18, N24: implementations create such a name as it is, or replace its bytes, also
    where the pax hdrcharset declares it."""
    h = bytearray(header("cafe"))
    h[3] = 0xE9
    for headers in [
        b"",
        extended(b"x", record("path", b"caf\xe9")),
        extended(b"L", b"caf\xe9\0"),
    ]:
        rejects(headers + checksum(h) + EOF, tmp_path, "not UTF-8")
    hdrcharset = record("hdrcharset", "BINARY") + record("path", "cafe")
    rejects(extended(b"x", hdrcharset) + member() + EOF, tmp_path, "hdrcharset")


@pytest.mark.parametrize("name", ["a\\b", "..\\a"])
def test_backslashes_in_names(tmp_path, name):
    """N13: a separator on Windows, and a character elsewhere."""
    rejects(member(name) + EOF, tmp_path, "backslash")


@needs_symlinks
def test_empty_symlink_target(tmp_path):
    """N25: os.symlink("") fails with ENOENT, which is not "symlinks are not supported"."""
    for archive in [
        member("s", type=b"2") + EOF,
        member("d/", type=b"5") + member("d/s", type=b"2") + EOF,
    ]:
        rejects(archive, tmp_path, "without a target")


# Kinds (K): whether a member is a file, a directory or a link.


@pytest.mark.parametrize(
    "headers,name",
    [
        (extended(b"x", record("path", "file")), "dir/"),
        (extended(b"L", b"file\0"), "dir/"),
        (extended(b"x", record("path", "dir/")), "file"),
    ],
    ids=["pax path", "GNU long name", "pax dir"],
)
def test_old_dirs_named_like_dirs_once(tmp_path, headers, name):
    """Old tar implementations write dirs as files named with a slash. Some implementations
    look for it in the name in the header, others in the final name: a file there has data,
    and a dir has none, which is where the others see a member."""
    archive = headers + header(name, b"\0", 1024) + member("hidden", bytes(1024)) + EOF
    rejects(archive, tmp_path, "named like a directory")


def test_old_dirs_named_like_dirs():
    archive = extended(b"x", record("path", "long/")) + header("dir/", b"\0", 0) + EOF
    assert members(archive) == [("long", "", 0)]


@pytest.mark.parametrize(
    "archive",
    [
        member("f", b"x", linkname="t"),
        member("d/", type=b"5", linkname="t"),
        extended(b"x", record("linkpath", "t")) + member("f", b"x"),
        extended(b"K", b"t\0") + member("f", b"x"),
    ],
    ids=["file", "dir", "pax linkpath", "GNU long link"],
)
def test_link_targets_of_other_kinds(tmp_path, archive):
    """K02: implementations that look at the link target rather than the type make a link
    of the member."""
    rejects(archive + EOF, tmp_path, "with a link target")


@pytest.mark.parametrize("name", ["file/", "dir/.", "dir/./"])
def test_non_directories_named_like_directories(tmp_path, name):
    """K01, K03: a regular file or a link named like a directory."""
    rejects(member(name, b"x") + EOF, tmp_path, "named like a directory")


# Order and state (S): members that interact, through one path or through links.


@pytest.mark.parametrize(
    "archive",
    [
        member("d/", type=b"5") + member("h", type=b"1", linkname="d") + EOF,
        member("h", type=b"1", linkname="") + EOF,
        member("h", type=b"1", linkname="h") + EOF,
        member("h", type=b"1", linkname="missing") + EOF,
    ],
)
def test_invalid_hardlinks(tmp_path, archive):
    """S03, S13: hardlinks to a dir, to nothing, to themselves only, or to a member that
    does not exist."""
    rejects(archive, tmp_path, "hardlinks")


def test_hardlink_to_itself(tmp_path):
    """S04: tar cf a.tar f f archives f twice, the second time as a hardlink to itself."""
    archive = member("f", b"x") + member("f", type=b"1", linkname="f") + EOF
    untar.extract(io.BytesIO(archive), str(tmp_path))
    assert (tmp_path / "f").read_bytes() == b"x"


@pytest.mark.skipif(
    sys.platform == "win32", reason="any symlink error means no privilege"
)
def test_copy_only_where_links_are_unsupported(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(os, "symlink", fail)
    with pytest.raises(OSError, match="I/O error"):
        untar.extract(
            io.BytesIO(member("t", b"x") + member("s", type=b"2", linkname="t") + EOF),
            str(tmp_path),
        )


# Compression: outside of the tar layer that tar-minefield covers.


def gzipped(size: int) -> bytes:
    return gzip.compress(make_tar([("f", "f", os.urandom(size), 0o644)]))


@pytest.mark.parametrize("size", [1000, 1046528, 1047040, 2095616])
def test_gzip_checksum(tmp_path, size):
    """Corrupt data is detected in archives of any size."""
    archive = bytearray(gzipped(size))
    archive[len(archive) // 2] ^= 1
    rejects(bytes(archive), tmp_path, "gzip")


@pytest.mark.parametrize("cut", [10, 100, 0.5, -8, -1])
def test_gzip_truncated(tmp_path, cut):
    archive = gzipped(100_000)
    end = int(len(archive) * cut) if isinstance(cut, float) else cut
    rejects(archive[:end], tmp_path)


def test_gzip_invalid(tmp_path):
    archive = bytearray(gzipped(1000))
    archive[2] = 9  # an unknown compression method
    rejects(bytes(archive), tmp_path, "gzip")


# The destination: what is already there, which no case of tar-minefield has.


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
def test_entries_in_the_destination_are_not_replaced(tmp_path):
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "a").write_text("mine")
    with pytest.raises(untar.Error, match="exists in the destination"):
        untar.extract(
            io.BytesIO(member("b", b"new") + member("a", b"theirs") + EOF), str(dest)
        )
    assert sorted(os.listdir(dest)) == ["a"]
    assert (dest / "a").read_text() == "mine"
