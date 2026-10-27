"""The test suite of tar-minefield, in tar-minefield/: archives, each a case with a verdict.

untar is a strict parser. It must reject every case to reject, and extract the tree in the
manifest of every case to accept. A tolerated case it may reject or extract, and REJECTED lists
those it rejects. A rejection leaves the destination empty, and no case writes outside of it.

As in tar-minefield, an error that untar raises is a rejection, and so is one of the operating
system that refuses an operation, such as creating a file that exists. Any other exception is a
crash, and fails the test."""

import hashlib
import json
import os
import posixpath
import stat
import sys
from pathlib import Path
from typing import Dict, Optional

import pytest
from test_untar import fail_with_eperm

import untar

SUITE = Path(__file__).parent / "tar-minefield"
CASES = sorted(path.stem for path in SUITE.glob("*.tar"))

#: The absolute name that N12 writes to in implementations that follow it
ABSOLUTE = "/tmp/tar-minefield-absolute"

#: Tolerated cases that untar rejects, by identifier
REJECTED = {
    "F02": "data after the end-of-archive marker could be a second archive",
    "F14": "the size field has room for the pax size, but gives another",
}

#: Cases where untar does not do as the verdict says, by identifier: to fix in untar
DISAGREES: Dict[str, str] = {}

#: The same, only where links are not supported and untar copies their targets
DISAGREES_WITHOUT_LINKS: Dict[str, str] = {}


def manifest(case: str) -> dict:
    with open(SUITE / f"{case}.json", encoding="utf-8") as f:
        return json.load(f)


def entry(path: Path) -> dict:
    """The entry of one path, as in the manifests."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        return {"kind": "symlink", "target": os.readlink(path)}
    if stat.S_ISDIR(st.st_mode):
        return {"kind": "directory"}
    data = path.read_bytes()
    return {
        "kind": "file",
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "executable": bool(st.st_mode & stat.S_IXUSR),
    }


def tree(top: Path) -> dict:
    """The tree under top: {path: entry}."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(top):
        for name in dirnames + filenames:
            path = Path(dirpath, name)
            out[path.relative_to(top).as_posix()] = entry(path)
    return out


def expected_tree(info: dict, links: bool) -> Optional[dict]:
    """The manifest's tree as {path: entry}. Where links are not supported, untar copies the
    target of a symlink instead, and must reject a symlink it cannot copy: then None."""
    expected = {
        e["path"]: {k: v for k, v in e.items() if k != "path"} for e in info["tree"]
    }
    if sys.platform == "win32":
        for e in expected.values():
            e.pop("executable", None)
    if links:
        return expected
    copies = {}
    for path, e in expected.items():
        target, seen = path, set()
        while e["kind"] == "symlink":
            target = posixpath.normpath(
                posixpath.join(posixpath.dirname(target), e["target"])
            )
            if target in seen or target not in expected:
                return None
            seen.add(target)
            e = expected[target]
            # The copy of a dir is its subtree: no case has a symlink to one yet
            assert e["kind"] != "directory"
        copies[path] = e
    return copies


def same(actual: dict, expected: dict) -> bool:
    """Whether a tree is the expected one, comparing what the manifest says of each entry."""
    return actual.keys() == expected.keys() and all(
        actual[path].get(k) == v for path, e in expected.items() for k, v in e.items()
    )


def params():
    for case in CASES:
        for links in ("supported", "unsupported"):
            reason = DISAGREES.get(case[:3])
            if links == "unsupported":
                reason = reason or DISAGREES_WITHOUT_LINKS.get(case[:3])
            marks = [pytest.mark.xfail(reason=reason, strict=True)] if reason else []
            yield pytest.param(case, links, marks=marks, id=f"{case}-{links}")


@pytest.mark.parametrize("case,links", list(params()))
def test_case(tmp_path, monkeypatch, case, links):
    info = manifest(case)
    if links == "unsupported":
        monkeypatch.setattr(os, "symlink", fail_with_eperm)
        monkeypatch.setattr(os, "link", fail_with_eperm)
    elif sys.platform == "win32" and any(
        e["kind"] == "symlink" for e in info.get("tree", [])
    ):
        pytest.skip("needs symlinks")
    absolute = os.path.lexists(ABSOLUTE)

    # Two levels down, so that what a name with .. writes outside dest is still in tmp_path
    dest = tmp_path / "x" / "y" / "dest"
    error = None
    try:
        untar.extract(str(SUITE / f"{case}.tar"), str(dest))
    except (untar.Error, OSError) as e:
        error = e

    assert os.listdir(tmp_path) == ["x"]
    assert os.listdir(tmp_path / "x") == ["y"]
    assert os.listdir(tmp_path / "x" / "y") == ["dest"]
    assert absolute or not os.path.lexists(ABSOLUTE)
    if error is not None:
        assert os.listdir(dest) == []

    if info["verdict"] == "reject":
        assert error is not None, f"accepts a case to reject, as {tree(dest)}"
        return
    expected = expected_tree(info, links == "supported")
    if expected is None or info["verdict"] == "tolerate" and info["id"] in REJECTED:
        assert error is not None, f"accepts it, as {tree(dest)}"
        return
    if error is not None:
        # A tree that the filesystem cannot store, such as a name with a newline on Windows,
        # is a failure of the platform: it passes when nothing was written
        if sys.platform == "win32" and not isinstance(error, untar.Error):
            return
        raise error
    actual = tree(dest)
    assert same(actual, expected), f"extracts {actual}, not {expected}"


def test_lists_name_cases():
    """Every case has a manifest, and the lists above name cases by their identifiers."""
    infos = [manifest(case) for case in CASES]
    assert infos and len(infos) == len(list(SUITE.glob("*.json")))
    ids = {info["id"] for info in infos}
    assert DISAGREES.keys() <= ids and DISAGREES_WITHOUT_LINKS.keys() <= ids
    tolerated = {info["id"] for info in infos if info["verdict"] == "tolerate"}
    assert REJECTED.keys() <= tolerated
