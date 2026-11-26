# cert-viewer
Admin tool to view and inspect multiple x509 Certificates

## Installation: 
use either of those 2 options

### Go:
```sh 
$ go install github.com/mgit-at/cert-viewer@latest
```
### Bazel: 
```sh 
$ bazel build //:cert-viewer
```
## Usage:
```sh
usage: cert-viewer [<flags>] <name>...

Flags:
  -h, --[no-]help            Show context-sensitive help (also try --help-long
                             and --help-man).
  -d, --[no-]disablesysroot  disable system root certificates from being used
  -j, --[no-]json            enable JSON output

Args:
  <name>  Filename of certificates (multiple files possible)
```
