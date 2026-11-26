package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func (tc testCert) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tc.cert.Raw})
}

func (tc testCert) keyPEM(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(tc.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

var testSerial int64

// newCert is self signed if parent is nil.
func newCert(t *testing.T, tmpl *x509.Certificate, parent *testCert) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	testSerial++
	tmpl.SerialNumber = big.NewInt(testSerial)
	if tmpl.NotAfter.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
		tmpl.NotAfter = time.Now().Add(time.Hour)
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCert{cert, key}
}

func newCA(t *testing.T, cn string, parent *testCert) testCert {
	t.Helper()
	return newCert(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, parent)
}

func newLeaf(t *testing.T, cn string, parent *testCert) testCert {
	t.Helper()
	return newCert(t, &x509.Certificate{
		Subject:        pkix.Name{Country: []string{"AT"}, CommonName: cn},
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:       []string{cn},
		EmailAddresses: []string{"admin@" + cn},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.1")},
		URIs:           []*url.URL{{Scheme: "https", Host: cn, Path: "/path", RawQuery: "q=1"}},
	}, parent)
}

type testPKI struct {
	root, inter, leaf testCert
}

func newPKI(t *testing.T) testPKI {
	t.Helper()
	root := newCA(t, "Test Root CA", nil)
	inter := newCA(t, "Test Intermediate CA", &root)
	return testPKI{root, inter, newLeaf(t, "leaf.example.com", &inter)}
}

func writeFile(t *testing.T, name string, parts ...[]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, bytes.Join(parts, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func parseAll(t *testing.T, certs ...testCert) entryList {
	t.Helper()
	var el entryList
	for _, c := range certs {
		blocks, err := decodePEM(c.pem(), "test.pem")
		if err != nil {
			t.Fatal(err)
		}
		if err := el.parse(blocks); err != nil {
			t.Fatal(err)
		}
	}
	return el
}

const pemA = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----"
const pemB = "-----BEGIN PRIVATE KEY-----\nREVG\n-----END PRIVATE KEY-----"

func TestFindPEMBlock(t *testing.T) {
	crlf := func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }
	tests := []struct {
		name, in, wantData, wantRest, wantErr string
	}{
		{name: "single block", in: "\n  " + pemA + "\n\n", wantData: pemA},
		{name: "two blocks", in: pemA + "\n\n" + pemB + "\n", wantData: pemA, wantRest: pemB},
		{name: "crlf", in: crlf(pemA + "\n" + pemB + "\n"), wantData: crlf(pemA), wantRest: crlf(pemB)},
		{name: "no pem", in: "hello world", wantErr: "no \"\\n-----BEGIN TYPE-----\""},
		{name: "text before block", in: "garbage\n" + pemA, wantErr: "unexpected symbol(s)"},
		{name: "missing end", in: "-----BEGIN CERTIFICATE-----\nQUJD\n", wantErr: "no \"\\n-----END TYPE-----\""},
		{name: "wrong end type", in: "-----BEGIN CERTIFICATE-----\nQUJD\n-----END PRIVATE KEY-----", wantErr: "wrong \"TYPE\""},
		{name: "text after end line", in: pemA + " garbage\n", wantErr: "found non whitespace"},
		{name: "nested begin", in: "-----BEGIN CERTIFICATE-----\n" + pemA, wantErr: "two \"-----BEGIN TYPE-----\" found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, rest, err := findPEMBlock([]byte(tt.in))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != tt.wantData || string(rest) != tt.wantRest {
				t.Errorf("got %q, %q; want %q, %q", data, rest, tt.wantData, tt.wantRest)
			}
		})
	}
}

func TestDecodePEM(t *testing.T) {
	pki := newPKI(t)

	blocks, err := decodePEM(bytes.Join([][]byte{pki.leaf.keyPEM(t), pki.leaf.pem(), pki.leaf.keyPEM(t), pki.inter.pem()}, nil), "f")
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 2 || blocks[0].src != (source{"f", 2}) || blocks[1].src != (source{"f", 4}) {
		t.Errorf("only the certificates at block 2 and 4 expected, got %+v", blocks)
	}

	// input without PEM is passed on, since it could be DER
	blocks, err = decodePEM(pki.leaf.cert.Raw, "leaf.der")
	if err != nil || len(blocks) != 1 || !bytes.Equal(blocks[0].block.Bytes, pki.leaf.cert.Raw) {
		t.Errorf("DER: err = %v, blocks = %+v", err, blocks)
	}

	_, err = decodePEM(append(pki.leaf.pem(), "garbage\n"...), "broken.pem")
	if err == nil || !strings.Contains(err.Error(), `file "broken.pem" at block "2"`) {
		t.Errorf("garbage after block: err = %v", err)
	}
}

func TestParse(t *testing.T) {
	pki := newPKI(t)

	var el entryList
	for _, name := range []string{"a.pem", "b.pem"} {
		blocks, err := decodePEM(pki.inter.pem(), name)
		if err != nil {
			t.Fatal(err)
		}
		if err := el.parse(blocks); err != nil {
			t.Fatal(err)
		}
	}
	if want := []source{{"a.pem", 1}, {"b.pem", 1}}; len(el) != 1 || !reflect.DeepEqual(el[0].source, want) {
		t.Errorf("duplicate certificate should be one entry with both sources, got %+v", el)
	}

	// leaf certificates have no subject key id, they must not be seen as duplicates
	el = parseAll(t, pki.leaf, newLeaf(t, "other.example.com", &pki.inter))
	if len(el) != 2 {
		t.Errorf("got %d entries for 2 different certificates", len(el))
	}
}

func TestVerifyAllCerts(t *testing.T) {
	pki := newPKI(t)

	for name, certs := range map[string][]testCert{
		"leaf first": {pki.leaf, pki.inter, pki.root},
		"root first": {pki.root, pki.inter, pki.leaf},
		"mixed":      {pki.inter, pki.leaf, pki.root},
	} {
		t.Run(name, func(t *testing.T) {
			el := parseAll(t, certs...)
			if err := el.verifyAllCerts(true); err != nil {
				t.Fatal(err)
			}
			chains := el.mergeChain()
			if len(chains) != 1 || len(chains[0]) != 3 {
				t.Fatalf("expected one chain with 3 certificates, got %d chains", len(chains))
			}
			for i, want := range []testCert{pki.leaf, pki.inter, pki.root} {
				if !chains[0][i].Equal(want.cert) {
					t.Errorf("chain[%d] = %s", i, chains[0][i].Subject.CommonName)
				}
			}
		})
	}

	t.Run("missing root", func(t *testing.T) {
		el := parseAll(t, pki.leaf, pki.inter)
		if err := el.verifyAllCerts(true); err != nil {
			t.Fatal(err)
		}
		for _, e := range el {
			if !errors.As(e.verified, new(x509.UnknownAuthorityError)) {
				t.Errorf("%s: verified = %v", e.cert.Subject.CommonName, e.verified)
			}
		}
		if chains := el.mergeChain(); len(chains) != 0 {
			t.Errorf("expected no chains, got %d", len(chains))
		}
	})

	t.Run("expired", func(t *testing.T) {
		expired := newCert(t, &x509.Certificate{
			NotBefore: time.Now().Add(-2 * time.Hour),
			NotAfter:  time.Now().Add(-time.Hour),
		}, &pki.inter)
		el := parseAll(t, expired, pki.inter, pki.root)
		if err := el.verifyAllCerts(true); err != nil {
			t.Fatal(err)
		}
		var invalid x509.CertificateInvalidError
		if !errors.As(el[0].verified, &invalid) || invalid.Reason != x509.Expired {
			t.Errorf("verified = %v", el[0].verified)
		}
	})

	t.Run("two leafs", func(t *testing.T) {
		el := parseAll(t, pki.leaf, newLeaf(t, "other.example.com", &pki.inter), pki.inter, pki.root)
		if err := el.verifyAllCerts(true); err != nil {
			t.Fatal(err)
		}
		var depths []int
		for _, j := range el.initJSONList(el.mergeChain()) {
			depths = append(depths, j.chaindepth)
		}
		if want := []int{0, 1, 2, 0, 1, 2}; !reflect.DeepEqual(depths, want) {
			t.Errorf("chain depths = %v, want %v", depths, want)
		}
	})
}
