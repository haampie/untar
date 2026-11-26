# tar-minefield

The archives and manifests of the test suite of
[tar-minefield](https://github.com/haampie/tar-minefield), `suite/archives/*.tar` and
`suite/archives/*.json` at commit `1021959b518fc94e3644d9b1897456a57b56f26f`, under the MIT
license. `tests/test_minefield.py` runs them.

**Some archives escape the directory they are extracted to in lenient implementations.** Their
files are harmless, and say in their names and contents what happened.

To update, from a checkout of tar-minefield:

```console
$ rm tests/tar-minefield/*.tar tests/tar-minefield/*.json
$ cp ../tar-minefield/suite/archives/*.{tar,json} tests/tar-minefield/
```
