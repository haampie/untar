"""``python -m untar <archive> <dest>``, like ``tar xf <archive> -C <dest>``."""

import os
import subprocess
import sys

import pytest
from test_untar import SAMPLE, make_tar, needs_symlinks, snapshot, tarfile_extract

import untar

#: For a subprocess to import the untar that the tests import
ENV = dict(os.environ, PYTHONPATH=os.path.dirname(os.path.abspath(untar.__file__)))


def run(cwd, *args, stdin=None):
    """Run python -m untar in cwd, on the untar that the tests import."""
    # Not capture_output, which needs Python 3.7
    return subprocess.run(  # noqa: UP022
        [sys.executable, "-m", "untar", *args],
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(cwd),
        env=ENV,
        check=False,
    )


@needs_symlinks
@pytest.mark.parametrize("stdin", [False, True])
def test_extracts_like_tar(tmp_path, stdin):
    data = make_tar(SAMPLE, compress=True)
    archive = tmp_path / "pkg.tar.gz"
    archive.write_bytes(data)
    dest = tmp_path / "a" / "b"
    if stdin:
        result = run(tmp_path, "-", str(dest), stdin=data)
    else:
        result = run(tmp_path, str(archive), str(dest))
    assert (result.returncode, result.stdout, result.stderr) == (0, b"", b"")
    tarfile_extract(data, tmp_path / "expected")
    assert snapshot(dest) == snapshot(tmp_path / "expected")


def test_errors(tmp_path):
    archive = tmp_path / "a.tar"
    archive.write_bytes(make_tar([("file", "f", b"new", 0o644)]))
    (tmp_path / "dest").mkdir()
    (tmp_path / "dest" / "file").write_bytes(b"old")
    result = run(tmp_path, str(archive), str(tmp_path / "dest"))
    assert result.returncode == 2
    assert result.stderr.decode().startswith("untar: file exists in the destination")
    assert os.listdir(tmp_path / "dest") == ["file"]
    assert (tmp_path / "dest" / "file").read_bytes() == b"old"

    result = run(tmp_path, str(tmp_path / "missing.tar"), str(tmp_path / "dest"))
    assert result.returncode == 2
    assert result.stderr.decode().startswith("untar: [Errno 2]")


def test_usage(tmp_path):
    result = run(tmp_path, str(tmp_path))
    assert result.returncode == 2
    assert b"usage: python -m untar" in result.stderr


def test_imports_no_compression(tmp_path):
    """The modules that decompress are imported when an archive needs them, not before."""
    code = "import sys, untar; print([m for m in ('gzip', 'bz2', 'lzma') if m in sys.modules])"
    out = subprocess.check_output(
        [sys.executable, "-S", "-c", code], cwd=str(tmp_path), env=ENV
    )
    assert out.strip() == b"[]"
