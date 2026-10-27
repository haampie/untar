# untar

This package extracts tarballs fast and safely, and is deliberately restricted to the subset of tar
features used to distribute software. It supports Python 3.6 and later.

It differs significantly from typical tar implementations: nothing is written outside the
destination or through a symlink, existing files are never replaced, owners and permissions from
the archive are not restored, and device files are rejected. On POSIX systems, entries are created
relative to open directory file descriptors. That rules out races where a directory is swapped for
a symlink between a check and its use, which implementations that work with paths are prone to.
Archives that tar implementations parse differently are rejected, and extraction happens in a
temporary directory, so an invalid or truncated archive leaves the destination untouched.

```python
import untar

# Extract an archive, from a path or any readable binary stream
untar.extract("pkg.tar.gz", "/opt/pkg")

# Extract the dir that contains `.meta`, wherever it is in the archive
root = untar.extract("pkg.tar.gz", "/opt/pkg", root_marker=".meta")
```

From the command line, like `tar xf pkg.tar.gz -C /opt/pkg`, with `-` to read standard input:

```console
$ python -m untar pkg.tar.gz /opt/pkg
```

Unlike tar, the destination is created if it does not exist, and an archive with an entry that
already exists there is an error, which exits with status 2.

## Scope

untar is for installing software from archives, not for restoring backups. Owners, groups,
timestamps and permissions recorded in an archive describe the machine it was made on; on
another machine they are meaningless at best and a liability at worst. So untar does not
restore them: files are created with `file_mode` (without executable bits where the archive
has none for the owner), dirs with `dir_mode`, optionally with group `gid`, and only regular
files, dirs, symlinks and hardlinks are extracted.

Files get the time they are extracted, unless `mtime` gives them all one modification time, at
the cost of a syscall per file. Pass it for autotools tarballs, where `configure` would otherwise
be older than `configure.ac` and make would run autoconf again; a fixed value makes extractions
reproducible.

## Features

- Streaming: the archive is read front to back once, without seeking, from a file, pipe or
  network stream. Gzip is detected from the first bytes.
- Fast parser: only the header fields that extraction needs are parsed (ustar, pax and GNU long
  names).
- Dynamic `--strip-components`: with `root_marker`, the parent of the shallowest member with
  that name is extracted, like `tar --strip-components` with a count that is only known after
  the last member.
- No path length limits: entries are created relative to open dir file descriptors, or on
  Windows by extended-length paths, so archives extract even where a member's full path would
  exceed the operating system's limit. Members can be up to 1024 dirs deep, since on macOS,
  creating an entry takes time linear in its depth.

## Decompressing in a thread

untar decompresses and extracts one after the other, in one thread, while `tar xzf` and
`gzip -d | tar xf -` decompress in another process at the same time. In Python, a thread can do
the same, since decompression and writes to a pipe release the GIL:

```python
import gzip
import os
import shutil
import threading

import untar


class Gunzip:
    """Decompress a gzip file in a thread, and read the result from a pipe."""

    def __init__(self, path):
        r, w = os.pipe()
        self.pipe = open(r, "rb", buffering=0)
        self.error = None
        self.thread = threading.Thread(target=self._decompress, args=(path, w))
        self.thread.start()

    def _decompress(self, path, w):
        try:
            # Writes block while the pipe is full, so decompression stays at most a pipe
            # buffer ahead of extraction
            with open(w, "wb") as out, gzip.open(path) as f:
                shutil.copyfileobj(f, out, 64 * 1024)
        except Exception as e:
            self.error = e

    def read(self, size):
        data = self.pipe.read(size)
        if not data:
            # The end of the pipe: wait until the gzip checksum is verified
            self.thread.join()
            if self.error:
                raise self.error
        return data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        # If extraction stopped early, a blocked write then fails, and the thread ends
        self.pipe.close()
        self.thread.join()


with Gunzip("pkg.tar.gz") as stream:
    untar.extract(stream, "/opt/pkg")
```

untar reads the stream to its end before it moves anything into the destination, so an archive
with a bad gzip checksum leaves the destination untouched.

## Safety

Absolute names and `..` are rejected, dirs are opened with `O_NOFOLLOW` so nothing is written
through a symlink, and files are created with `O_EXCL | O_NOFOLLOW` so existing entries are never
replaced. Symlinks may point anywhere, but untar never follows them, except where the destination
itself is one. The destination can also be an open dir file descriptor, so that a caller who
opened it safely extracts into that very dir.

On Windows, which has no dir file descriptors, entries are created by path. Every dir leading to
the current member is held open without sharing delete access, so that neither it nor its
ancestors can be renamed or removed, and none can be swapped for a symlink or junction while it is
in use. Files are created with `CREATE_NEW` and `FILE_FLAG_OPEN_REPARSE_POINT`, the counterpart of
`O_EXCL | O_NOFOLLOW`, and symlinks and junctions on the path to the destination are resolved
once (from Python 3.8 on, whose `realpath` resolves them on Windows).

Parsing is relatively strict: the idea is to reject tar files that would extract differently
under tar implementations with more lenient parsing. Numbers must be plain digits, a member's name
and size come from one header only, global pax headers cannot set them, names must be UTF-8
without a NUL or backslash inside, only links have a link target, and links, dirs, devices and
fifos cannot have a size. The rules are those of the default policy of
[tar-minefield](https://github.com/haampie/tar-minefield), except that symlinks may point out of
the archive, since untar does not follow them. The gzip checksum is always
verified, and an archive must end with two zero blocks and only zeros after them, so that neither
truncation between members nor a second archive after the first goes unnoticed.

## Development

```console
$ pip install -e '.[dev]'
$ python tests/vendor/fetch_cpython_testdata.py cpython-testdata
$ UNTAR_CPYTHON_TESTDATA=cpython-testdata pytest
$ ruff check && ruff format --diff && mypy
```

`tests/tar-minefield` is the test suite of [tar-minefield](https://github.com/haampie/tar-minefield),
whose verdicts `tests/test_minefield.py` checks, and whose language the tests use: cases with
an identifier such as `F12`, in the categories framing (F), names (N), kinds (K), and order and
state (S), to reject, accept or tolerate.

`tests/vendor/test_cpython.py` is adapted from CPython's `test_tarfile.py` and is under the PSF
License Agreement included in it. The rest of untar is under the MIT license.
