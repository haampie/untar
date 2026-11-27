# untar

`untar` is a Python library for extracting tar archives with high performance and strong safety
guarantees. It targets software distribution archives (source tarballs, packages, release artifacts)
rather than filesystem backups, and supports Python 3.6 and later with no dependencies.

## Usage

```python
import untar

# Extract an archive from a file path or any readable binary stream, compressed or not
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

An invalid or unsafe archive raises `untar.Error`, and one compressed in a format that this Python
cannot decompress raises its subclass `untar.UnsupportedCompression`. Operations that the operating
system refuses raise `OSError` instead, notably `FileExistsError` for a name that occurs twice in an
archive, since entries are never replaced. Catch `(untar.Error, OSError)` to handle every rejected
archive.

### Options

`untar.extract(src, dest, *, root_marker=None, file_mode=0o755, dir_mode=0o755, gid=None, mtime=None)`:

- `src`: a file path or any readable binary stream. Compression with gzip, bzip2, xz or zstd is
  detected from the first bytes; zstd needs Python 3.14 or later.
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
  destination and moved into place only after the full stream (including the checksum of its
  compression) has been read and verified. An invalid archive leaves the destination untouched, as
  does a truncated one that is compressed or cut inside a member. The end-of-archive marker is
  optional (ruby's release tarballs lack it), so an uncompressed archive cut exactly between two
  members cannot be told apart from a complete one.
- **No traversal or overwrites:** Absolute paths, `..` components, backslashes, and Windows drive
  letters are rejected. Directories are opened with `O_NOFOLLOW` and files are created with
  `O_EXCL | O_NOFOLLOW`, so `untar` never writes through symlinks or overwrites existing files.
  Symlinks and hardlinks are extracted, while device nodes, FIFOs, and sparse files are rejected.
  Where the platform or filesystem does not support links, the file a link points to is copied
  instead, and a symlink that cannot be copied (one to a directory, or to a target outside the
  archive) is an error rather than silently dropped.
  On Windows, where creating symlinks takes a privilege or developer mode, the separators in a
  symlink's target are stored as backslashes, and a symlink to a directory in the archive is created
  as one, also when that directory comes later in the archive: other symlinks lead nowhere there.
- **Race-free directory traversal:** On POSIX, entries are created relative to open directory file
  descriptors (`dir_fd`), preventing time-of-check-to-time-of-use (TOCTOU) races where a directory
  is swapped for a symlink during extraction and avoiding OS `PATH_MAX` limits. On Windows, which
  lacks `dir_fd`, `untar` uses extended-length paths (`\\?\`), creates files with
  `CREATE_NEW | FILE_FLAG_OPEN_REPARSE_POINT`, and keeps every directory on the path to an entry
  open: without delete sharing, so that neither the directory nor its ancestors can be renamed or
  removed, and with a file in it that only `untar` can remove, since Windows lets only an empty
  directory be made a junction or symlink. Whether a directory is a plain one is asked of its open
  handle rather than of its path, and so is where the destination is once links on the way to it
  are resolved.
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
