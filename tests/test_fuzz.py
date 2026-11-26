"""Structure-aware fuzzing: one header field at a time gets an odd value, and the checksum is
recomputed, so that mutations get past the checksum. Whatever the archive, reading must make
progress and raise only untar.Error, and extracting must raise only untar.Error or OSError and
change nothing outside the destination."""

import gzip
import io
import itertools
import os
import random
import shutil
import tarfile

import pytest
from test_untar import SAMPLE, fail_with_eperm, make_tar, needs_symlinks, snapshot

import untar

FIELDS = {
    "name": (0, 100),
    "mode": (100, 108),
    "size": (124, 136),
    "type": (156, 157),
    "linkname": (157, 257),
    "magic": (257, 265),
    "prefix": (345, 500),
}

NUMBERS = [
    b"-1777",
    b"+17",
    b"0o17",
    b"0_17",
    b"1 7",
    b"",
    b" " * 11,
    b"0",
    b"1",
    b"777",
    b"77777777777",
    b"00000755",
    b"000000000012",
    b"\x80" + bytes(10) + b"\x10",
    b"\x80" + b"\xff" * 11,
    b"\xff" * 12,
    b"\xd9\xa3",
]

VALUES = {
    "name": [
        b"",
        b".",
        b"..",
        b"/abs",
        b"a/../b",
        b"a//b",
        b"./a",
        b"a/",
        b"a/.",
        b"C:/a",
        b"a\0b",
        b"\xff\xfe",
    ],
    "mode": NUMBERS,
    "size": NUMBERS,
    "type": [bytes([t]) for t in b"012345675xgLKSXZ\0"],
    "linkname": [
        b"",
        b".",
        b"..",
        b"/etc",
        b"pkg",
        b"../pkg",
        b"pkg/bin/app",
        b"pkg/bin/app/",
        b"pkg\0x",
        b"\0x",
        b"\xff\xfe",
    ],
    "magic": [b"ustar\x0000", b"ustar  \0", b"ustar\0\0\0", bytes(8)],
    "prefix": [b"", b"pkg", b"/", b"..", b"a/b"],
}

RECORDS = [
    b"5 abc\n",
    b"6 =abc\n",
    b"10 size=0\n",
    b"13 size=-512\n",
    b"11 size=1_0\n",
    b"13 path=a/..\n",
    b"12 path=a\0b\n",
    b"9 path=\n",
    b"16 linkpath=/etc\n",
    b"+9 path=x\n",
    b"99 path=x\n",
    b"25 GNU.sparse.size=1000\n",
    b"13 mode=0755\n",
    b"15 comment=a\nb\n",
    b"17 linkpath=caf\xe9\n",
    b"17 linkpath=a\nb/\n",
]


def archives():
    gnu = make_tar(SAMPLE, tarfile.GNU_FORMAT)
    pax = make_tar(SAMPLE, tarfile.PAX_FORMAT)
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT) as tar:
        tar.pax_headers = {"comment": "global"}
        for name in ("a", "b/c"):
            info = tarfile.TarInfo(name)
            info.size = 3
            tar.addfile(info, io.BytesIO(b"abc"))
    return [gnu, pax, out.getvalue()]


def headers(archive: bytes):
    """Offsets of the blocks that are headers."""
    offsets = []
    for offset in range(0, len(archive), 512):
        block = archive[offset : offset + 512]
        try:
            if block != bytes(512) and untar._checksum_ok(block):
                offsets.append(offset)
        except untar.Error:
            pass
    return offsets


def checksum(block: bytearray) -> None:
    block[148:156] = b" " * 8
    block[148:156] = b"%06o\0 " % sum(block)


def mutate(archive: bytes, rng: random.Random) -> bytes:
    data = bytearray(archive)
    for _ in range(rng.choice([1, 1, 2, 3])):
        offset = rng.choice(headers(archive))
        if data[offset + 156 : offset + 157] in (b"x", b"g") and rng.random() < 0.3:
            # Replace the pax records, keeping the header's size
            records = b"".join(rng.sample(RECORDS, rng.randint(1, 3)))
            try:
                size = untar._int(bytes(data[offset + 124 : offset + 136]))
            except untar.Error:
                continue
            if size > len(data):
                # A size that an earlier round wrote
                continue
            data[offset + 512 : offset + 512 + size] = records[:size].ljust(size, b"\0")
            continue
        field = rng.choice(list(FIELDS))
        start, end = FIELDS[field]
        value = rng.choice(VALUES[field])
        if rng.random() < 0.1:
            value = bytes(rng.randrange(256) for _ in range(end - start))
        data[offset + start : offset + end] = value[: end - start].ljust(
            end - start, b"\0"
        )
        block = data[offset : offset + 512]
        checksum(block)
        data[offset : offset + 512] = block
    return bytes(data)


def check_reader(archive: bytes) -> None:
    """The reader ends within the number of blocks, and raises only untar.Error."""
    limit = len(archive) // 512 + 1
    reader = untar.TarReader(io.BytesIO(archive))
    try:
        count = 0
        for _ in itertools.islice(reader, limit + 1):
            for _ in reader.chunks():
                pass
            count += 1
        assert count <= limit, "the reader does not make progress"
    except untar.Error:
        pass


def check_extract(archive: bytes, outer) -> None:
    """Extracting raises only untar.Error or OSError, and changes nothing outside dest."""
    flag = outer / "flag"
    dest = outer / "dest"
    try:
        untar.extract(io.BytesIO(archive), str(dest))
    except (untar.Error, OSError):
        pass
    assert sorted(os.listdir(outer)) == ["dest", "flag"]
    assert flag.read_bytes() == b"flag"
    assert not [n for n in os.listdir(dest) if n.startswith(".untar-")]
    shutil.rmtree(dest)


@needs_symlinks
@pytest.mark.parametrize("links", ["supported", "unsupported"])
def test_fuzz_fields(tmp_path, monkeypatch, links):
    if links == "unsupported":
        monkeypatch.setattr(os, "symlink", fail_with_eperm)
        monkeypatch.setattr(os, "link", fail_with_eperm)
    outer = tmp_path / "outer"
    outer.mkdir()
    (outer / "flag").write_bytes(b"flag")
    rng = random.Random(f"fields-{links}")
    bases = archives()
    for _ in range(int(os.environ.get("UNTAR_FUZZ", "600"))):
        archive = mutate(rng.choice(bases), rng)
        check_reader(archive)
        check_extract(archive, outer)


@needs_symlinks
def test_fuzz_gzip(tmp_path):
    """Truncated or corrupted gzip fails, or extracts exactly the original tree."""
    plain = make_tar(SAMPLE)
    untar.extract(io.BytesIO(plain), str(tmp_path / "expected"))
    expected = snapshot(tmp_path / "expected")
    compressed = gzip.compress(plain)
    rng = random.Random("gzip")
    outcomes = {"error": 0, "same": 0}
    for i in range(300):
        data = bytearray(compressed)
        if rng.random() < 0.3:
            data = data[: rng.randrange(len(data))]
        else:
            for _ in range(rng.randint(1, 4)):
                data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
        dest = tmp_path / str(i)
        try:
            untar.extract(io.BytesIO(bytes(data)), str(dest))
        except untar.Error:
            outcomes["error"] += 1
            continue
        assert snapshot(dest) == expected
        outcomes["same"] += 1
    assert outcomes["error"] > 0
