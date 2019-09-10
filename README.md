# cert-viewer
Tool to view x509 Certificates. 
## Installation: 
use either of those 2 options

### Go:
```sh 
$ go get github.com/mgit-at/cert-viewer
```
### Bazel: 
```sh 
$ bazel build //:cert-viewer
```
## Usage:
```sh
usage: cert-viewer [<flags>] <name>...

Flags:
  --help            Show context-sensitive help (also try --help-long and --help-man).
  --disablesysroot  disable system root certificates from being used
  --json            enable JSON output

Args:
  <name>  filename and/or directory paths
```
