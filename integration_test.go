package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The tests here run the real main() in a new process, by executing the test
// binary itself with envRunMain set. This also works for bazel test, where
// no go toolchain is available to build the binary.
const envRunMain = "CERT_VIEWER_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(envRunMain) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

func certViewer(t *testing.T, wantCode int, args ...string) (stdout, stderr string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), envRunMain+"=1")
	var outbuf, errbuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &outbuf, &errbuf
	code := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatal(err)
		}
		code = exitErr.ExitCode()
	}
	if code != wantCode {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, wantCode, &outbuf, &errbuf)
	}
	return outbuf.String(), errbuf.String()
}

func expectContains(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Errorf("%q is missing in:\n%s", want, got)
		}
	}
}

func TestCLIUsage(t *testing.T) {
	const usage = "usage: cert-viewer [<flags>] <name>..."

	stdout, stderr := certViewer(t, 0, "--help")
	expectContains(t, stdout, usage, "-d, --disablesysroot", "-j, --json", "-V, --version")
	if stderr != "" {
		t.Errorf("unexpected stderr: %s", stderr)
	}

	stdout, stderr = certViewer(t, 1)
	expectContains(t, stderr, usage)
	if stdout != "" {
		t.Errorf("unexpected stdout: %s", stdout)
	}

	_, stderr = certViewer(t, 2, "--nonexistent")
	expectContains(t, stderr, "unknown flag: --nonexistent", usage)

	stdout, _ = certViewer(t, 0, "--version")
	if !strings.HasPrefix(stdout, "cert-viewer ") {
		t.Errorf("version output = %q", stdout)
	}
}

func TestCLIErrors(t *testing.T) {
	pki := newPKI(t)
	tests := []struct{ name, path, want string }{
		{"missing file", filepath.Join(t.TempDir(), "missing.pem"), "failed to stat file"},
		{"directory only", t.TempDir(), "No certificates found"},
		{"only a key", writeFile(t, "key.pem", pki.leaf.keyPEM(t)), "No certificates found"},
		{"not a certificate", writeFile(t, "hello.txt", []byte("hello world\n")), "failed to decode"},
		{"garbage after certificate", writeFile(t, "garbage.pem", pki.leaf.pem(), []byte("garbage\n")), "failed to decode"},
		{"broken certificate", writeFile(t, "broken.pem", []byte(pemA+"\n")), "failed to parse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr := certViewer(t, 1, "-d", tt.path)
			expectContains(t, stderr, "[ERROR] ", tt.want)
			if stdout != "" {
				t.Errorf("unexpected stdout: %s", stdout)
			}
		})
	}
}

func TestCLIChain(t *testing.T) {
	pki := newPKI(t)
	path := writeFile(t, "chain.pem", pki.root.pem(), pki.leaf.keyPEM(t), pki.leaf.pem(), pki.inter.pem())

	stdout, _ := certViewer(t, 0, "-d", path)

	leaf := strings.Index(stdout, " Subject          : C = AT, CN = leaf.example.com\n")
	inter := strings.Index(stdout, "\n     Subject          : CN = Test Intermediate CA\n")
	root := strings.Index(stdout, "\n         Subject          : CN = Test Root CA\n")
	if leaf != 0 || inter < leaf || root < inter {
		t.Errorf("chain is not printed from leaf to root, indented by depth:\n%s", stdout)
	}
	expectContains(t, stdout,
		" Issuer           : CN = Test Intermediate CA\n",
		" Key Usage        : Digital Signature\n",
		" Ext Key Usage    : Server Authentication\n",
		" Alt Names        : DNS:leaf.example.com, EMAIL:admin@leaf.example.com, IP:192.0.2.1, URL:https://leaf.example.com/path?q=1\n",
		" Verified         : true\n",
		" Source           : "+path+" | Block: 3\n",
		"         Verified         : true (self signed)\n",
		"         Source           : "+path+" | Block: 1\n",
	)
}

func TestCLIJSON(t *testing.T) {
	pki, other := newPKI(t), newPKI(t)
	chainPath := writeFile(t, "chain.pem", pki.leaf.pem(), pki.inter.pem(), pki.root.pem())
	dupPath := writeFile(t, "dup.pem", pki.leaf.pem())
	unverifiedPath := writeFile(t, "unverified.pem", other.leaf.pem())

	stdout, _ := certViewer(t, 0, "--disablesysroot", "--json", unverifiedPath, chainPath, dupPath)

	var entries []jsonEntry
	if err := json.Unmarshal([]byte(stdout), &entries); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 certificates, got %d:\n%s", len(entries), stdout)
	}
	for i, cn := range []string{"leaf.example.com", "Test Intermediate CA", "Test Root CA"} {
		if entries[i].Subject.CommonName != cn || !entries[i].Verified.Status {
			t.Errorf("entry %d: %+v", i, entries[i])
		}
	}
	leaf := entries[0]
	if len(leaf.Source) != 2 || leaf.Source[0] != (source{chainPath, 1}) || leaf.Source[1] != (source{dupPath, 1}) {
		t.Errorf("leaf sources = %+v", leaf.Source)
	}
	if !leaf.Validity.NotAfter.Equal(pki.leaf.cert.NotAfter) {
		t.Errorf("not after = %v, want %v", leaf.Validity.NotAfter, pki.leaf.cert.NotAfter)
	}
	// the key was misspelled once, and is not seen when decoding into jsonEntry
	expectContains(t, stdout, `"url": [`)

	unverified := entries[3]
	if unverified.Source[0].Name != unverifiedPath || unverified.Verified.Status {
		t.Errorf("unverified certificates should be printed last: %+v", unverified)
	}
	expectContains(t, unverified.Verified.Info, "unknown authority")
}

func TestCLIInputs(t *testing.T) {
	pki := newPKI(t)
	tests := []struct {
		name string
		args []string
	}{
		{"DER", []string{writeFile(t, "leaf.der", pki.leaf.cert.Raw)}},
		{"CRLF", []string{writeFile(t, "crlf.pem", bytes.ReplaceAll(pki.leaf.pem(), []byte("\n"), []byte("\r\n")))}},
		{"space in filename", []string{writeFile(t, "foo bar.pem", pki.leaf.pem())}},
		{"directory is skipped", []string{t.TempDir(), writeFile(t, "leaf.pem", pki.leaf.pem())}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _ := certViewer(t, 0, append([]string{"-d"}, tt.args...)...)
			expectContains(t, stdout, "CN = leaf.example.com\n", " Source           : "+tt.args[len(tt.args)-1]+" | Block: 1\n")
		})
	}
}
