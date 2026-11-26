# cert-viewer
Admin tool to view and inspect multiple x509 Certificates

It reads certificates (PEM or DER) from one or more files, verifies them
against each other and the system root certificates, and shows them sorted by
their certificate chains.

## Installation:
use either of those options

### Release binaries:
Binaries for Linux, macOS and Windows (amd64 and arm64) are available on the
[releases page](https://github.com/mgit-at/cert-viewer/releases).

### Debian package:
Download the `.deb` for your architecture from the
[releases page](https://github.com/mgit-at/cert-viewer/releases) and install it:
```sh
$ sudo dpkg -i cert-viewer_*_linux_amd64.deb
```
### Go:
```sh
$ go install github.com/mgit-at/cert-viewer@latest
```
## Usage:
```sh
usage: cert-viewer [<flags>] <name>...

Flags:
  -h, --help             show this help message
  -d, --disablesysroot   disable system root certificates from being used
  -j, --json             enable JSON output
  -V, --version          show the version

Args:
  <name>  Filename of certificates (multiple files possible)
```
## Development:
```sh
$ go test ./...    # unit and integration tests
```
The integration tests run the real binary against certificates generated
during the test.

The Bazel build (`bazel build //:cert-viewer`, `bazel test //...`) is only kept
as reference, releases are built with [GoReleaser](https://goreleaser.com).

### Release:
1. tag and push: `git tag -a v1.2.3 -m v1.2.3 && git push origin v1.2.3`
2. the release workflow builds binaries, debian packages and checksums with
   GoReleaser and creates a draft release on GitHub
3. review and publish the draft release

To build the release artifacts locally: `goreleaser release --snapshot --clean`
