# untar

`untar` is a Python library for extracting tar archives with high performance and strong safety
guarantees. It targets software distribution archives (source tarballs, packages, release artifacts)
rather than filesystem backups, and supports Python 3.6 and later with no dependencies.

## Usage

```python
import untar

# Extract an archive from a file path or any readable binary stream (.tar or .tar.gz)
untar.extract("pkg.tar.gz", "/opt/pkg")

# Extract the directory containing `.meta`, wherever it appears in the archive
root = untar.extract("pkg.tar.gz", "/opt/pkg", root_marker=".meta")
```

From the command line (use `-` for standard input):

```console
$ python -m untar pkg.tar.gz /opt/pkg
```

The destination directory is created if it does not exist. If any top-level entry from the archive
already exists in the destination, extraction fails and leaves the destination unchanged (exiting
with status 2 on the CLI).

### Options

`untar.extract(src, dest, *, root_marker=None, file_mode=0o755, dir_mode=0o755, gid=None, mtime=None)`:

- `src`: a file path or any readable binary stream. Gzip compression is detected automatically from
  the first two bytes.
- `dest`: a directory path or, on POSIX, an open directory file descriptor.
- `root_marker`: extract only the parent directory of the shallowest member with this filename, and
  return that directory's path in the archive (similar to `tar --strip-components` when the nesting
  depth is not known in advance). All other members must reside under that directory.
- `file_mode`, `dir_mode`, `gid`: permissions and group applied to extracted files and directories.
  Archive ownership and mode bits are ignored, except that a file only receives executable bits from
  `file_mode` when the archive marks it executable by its owner (`0o100`).
- `mtime`: optional modification time (in seconds since the epoch) applied to all extracted files.
  By default, files keep their extraction timestamp; setting a uniform `mtime` avoids timestamp skew
  in archives such as autotools releases where `configure` is stored before `configure.ac`.

## Safety

- **Atomic against archive errors:** Members are extracted into a temporary directory inside the
  destination and moved into place only after the full stream (including the gzip checksum) has been
  read and verified. An invalid archive leaves the destination untouched, as does a truncated one
  that is compressed or cut inside a member. The end-of-archive marker is optional (ruby's release
  tarballs lack it), so an uncompressed archive cut exactly between two members cannot be told
  apart from a complete one.
- **No traversal or overwrites:** Absolute paths, `..` components, backslashes, and Windows drive
  letters are rejected. Directories are opened with `O_NOFOLLOW` and files are created with
  `O_EXCL | O_NOFOLLOW`, so `untar` never writes through symlinks or overwrites existing files.
  Symlinks and hardlinks are extracted (or copied when the platform or filesystem does not support
  links), while device nodes, FIFOs, and sparse files are rejected.
- **Race-free directory traversal:** On POSIX, entries are created relative to open directory file
  descriptors (`dir_fd`), preventing time-of-check-to-time-of-use (TOCTOU) races where a directory
  is swapped for a symlink during extraction and avoiding OS `PATH_MAX` limits. On Windows, which
  lacks `dir_fd`, `untar` uses extended-length paths (`\\?\`), creates files with
  `CREATE_NEW | FILE_FLAG_OPEN_REPARSE_POINT`, and holds ancestor directories open without delete
  sharing so they cannot be renamed, removed, or replaced with junctions or symlinks during
  extraction.
- **Strict, unambiguous parsing:** `untar` follows the default policy of
  [tar-minefield](https://stoppels.ch/tar) to reject ambiguous archives that different tar
  implementations interpret differently (such as conflicting extended headers, non-octal numeric
  fields, non-UTF-8 paths, embedded NUL bytes, trailing data after the end-of-archive marker, or
  sizes on non-file entries). Header fields that `untar` does not use (`uid`, `gid`, `mtime`,
  `uname`, `gname`, and the ustar `name` of an extended header block) are skipped so parsing does
  not pay to validate unused metadata.

## Performance

`untar` reads the stream once from front to back without seeking, parses only the header fields
required for extraction, and keeps a stack of open ancestor directory descriptors so typical
depth-first archives rarely reopen parent directories.

### Decompressing in a thread

`untar` decompresses and extracts sequentially on the calling thread, whereas `tar xzf` and
`gzip -d | tar xf -` overlap decompression and extraction across processes. You can overlap them in
Python by running `gzip` in a background thread that writes to a pipe, as both `zlib` and pipe
writes release the GIL:

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
            # Writes block while the pipe is full, keeping decompression at most one pipe
            # buffer ahead of extraction
            with open(w, "wb") as out, gzip.open(path) as f:
                shutil.copyfileobj(f, out, 64 * 1024)
        except Exception as e:
            self.error = e

    def read(self, size):
        data = self.pipe.read(size)
        if not data:
            # End of pipe: wait for the thread so any gzip checksum error is raised
            self.thread.join()
            if self.error:
                raise self.error
        return data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        # If extraction aborts early, closing the read end unblocks the writer thread
        self.pipe.close()
        self.thread.join()


with Gunzip("pkg.tar.gz") as stream:
    untar.extract(stream, "/opt/pkg")
```

## Development

```console
$ pip install -e '.[dev]'
$ python tests/vendor/fetch_cpython_testdata.py cpython-testdata
$ UNTAR_CPYTHON_TESTDATA=cpython-testdata pytest
$ ruff check && ruff format --diff && mypy
```

`tests/tar-minefield` vendors the [tar-minefield](https://github.com/haampie/tar-minefield) test
suite; `tests/test_minefield.py` lists the few cases where `untar` intentionally differs (`ACCEPTED`
for unused header fields that are not parsed, and `REJECTED` for tolerated cases that `untar`
refuses). `tests/vendor/test_cpython.py` is adapted from CPython's `test_tarfile.py` under the PSF
License Agreement; the rest of `untar` is under the MIT license.
