package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"gopkg.in/alecthomas/kingpin.v2"
)

/*
features:
multiple files
split source into 2 / source and sourcepos
json output
*/

type entry struct {
	cert     *x509.Certificate
	Source   string `json:"source"`
	chain    [][]*x509.Certificate
	verified error
}

type entrylist []entry

func main() {
	if err := run(); err != nil {
		log.Fatal("[ERROR] ", err)
	}
}

func run() error {
	var (
		name       = kingpin.Arg("name", "filename").Required().String()
		usesysroot = kingpin.Flag("usesysroot", "Should Sysroot be used").Default("true").Bool()
	)
	kingpin.Version("0.0.1")
	kingpin.Parse()

	certPEM, err := ioutil.ReadFile(*name)
	if err != nil {
		return errors.Wrapf(err, "failed to read file %q", *name)
	}

	blocklist, err := decode(certPEM)
	if err != nil {
		return errors.Wrap(err, "failed to decode PEM")
	}

	certlist, err := parse(blocklist, *name)
	if err != nil {
		return errors.Wrap(err, "failed to parse")
	}

	if err := certlist.verifyAllCerts(*usesysroot); err != nil {
		return errors.Wrap(err, "failed to verify")
	}

	certlist.printCerts()

	data, err := json.MarshalIndent(certlist, "", "  ")
	fmt.Fprintf(os.Stdout, "%s\n", data)

	//	chain := certlist.mergeChain()
	//
	//	printChain(chain)

	return nil
}

func decode(certPEM []byte) ([]*pem.Block, error) {
	var blocklist []*pem.Block
	for {
		block, rest := pem.Decode(certPEM)
		if block == nil {
			break
		}
		if !strings.Contains(block.Type, "CERTIFICATE") {
			continue
		}
		blocklist = append(blocklist, block)
		certPEM = rest
	}
	if len(blocklist) == 0 {
		return nil, errors.New("No certificates to check")
	}
	return blocklist, nil
}

func parse(blocklist []*pem.Block, name string) (entrylist, error) {
	var el entrylist
	for i, block := range blocklist {
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse PEM block")
		}
		e := entry{
			cert:   c,
			Source: name + " | Certificate: " + strconv.Itoa(i),
		}
		el = append(el, e)
	}
	return el, nil
}

func (el entrylist) verifyAllCerts(usesysroot bool) error {
	pool, roots := x509.NewCertPool(), x509.NewCertPool()
	if usesysroot {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return err
		}
	}

	wip, notdone := true, true
	for wip && notdone {
		wip, notdone = false, false
		for idx, curentry := range el {
			if curentry.chain != nil {
				continue
			}
			curentry.chain, curentry.verified = verify(curentry, pool, roots)
			switch errors.Cause(curentry.verified).(type) {
			case x509.SystemRootsError:
				return curentry.verified
			case nil:
				wip = true
			}
			notdone = notdone || (curentry.verified != nil)
			el[idx] = curentry
		}
	}
	return nil
}

func verify(e entry, pool *x509.CertPool, root *x509.CertPool) ([][]*x509.Certificate, error) {
	if isSelfSignedRoot(e.cert) {
		root.AddCert(e.cert)
	}
	opts := x509.VerifyOptions{
		Intermediates: pool,
		Roots:         root,
	}

	chain, err := e.cert.Verify(opts)
	if err != nil {
		return nil, err
	}
	pool.AddCert(e.cert)
	return chain, nil
}

func isSelfSignedRoot(cert *x509.Certificate) bool {
	if cert.AuthorityKeyId != nil {
		return string(cert.AuthorityKeyId) == string(cert.SubjectKeyId) && cert.IsCA
	}
	return cert.Subject.String() == cert.Issuer.String() && cert.IsCA
}

/*
func (el entrylist) mergeChain() ([][]*x509.Certificate, error) {
	var comchain [][]*x509.Certificate
	maxsize := 0
	for _, v := range el {
		for _, c := range v.chain {
			comchain = append(comchain, c)
			if len(c) > maxsize {
				maxsize = len(c)
			}
		}
	}

	var redchain [][]*x509.Certificate
	redchain = append(redchain, comchain[0])
	if len(comchain) > 1 {
		for i, v := range comchain[1:] {
			if !compareChain(comchain[i], v) {
				redchain = append(redchain, v)
			}
		}
	}
	return redchain, nil
}

func compareChain(chain1, chain2 []*x509.Certificate) bool {
	if len(chain1) < len(chain2) {
		chain1, chain2 = chain2, chain1
	}
	dif := len(chain1) - len(chain2)
	for i := len(chain1) - 1; i > 0; i-- {
		if chain1[i] != chain2[i-dif] {
			return false
		}
	}

	return true
}

func compareCert(cert1, cert2 *x509.Certificate) bool {
	return string(cert2.SubjectKeyId) == string(cert1.SubjectKeyId)
}

func printChain(chain [][]*x509.Certificate) {
	for _, chainval := range chain {
		for certidx, certval := range chainval {
			//if certval != curentry.cert {
			//cert := entry{certval, "Chain from: "  + curentry.source, nil, nil}
			//cert := entry{certval, "Chain from: ", nil, nil}
			fmt.Println("-  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  ")
			printEntry(cert, certidx)
			//}
		}
	}
	fmt.Println("------------------------------------------------------------------------------------------------------------")
	fmt.Println()
}*/

func (el entrylist) printCerts() {
	fmt.Println()
	for i, curentry := range el {

		if i > 0 {
			fmt.Println(strings.Repeat("=", 100))
			fmt.Println()
		}

		printEntry(curentry, 0)
		for _, chainval := range curentry.chain {
			for certidx, certval := range chainval {
				if certval != curentry.cert {
					cert := entry{certval, "Chain from: " + curentry.Source, nil, nil}
					fmt.Println(strings.Repeat("- ", 50))
					printEntry(cert, certidx)
				}
			}
		}
	}
}

func printEntry(e entry, tabcount int) {
	tab := strings.Repeat(" ", tabcount*4)
	printName(e.cert.Subject)
	fmt.Println(tab, "Subject       :", printName(e.cert.Subject))
	fmt.Println(tab, "Version       :", e.cert.Version)
	fmt.Println(tab, "Serial Number :", encodeHex(e.cert.SerialNumber.Bytes()))
	fmt.Println(tab, "Sign Algo     :", e.cert.SignatureAlgorithm)
	fmt.Println(tab, "Issuer        :", printName(e.cert.Issuer))
	fmt.Println(tab, "Validity:")
	fmt.Println(tab, "  Not Before  :", e.cert.NotBefore)
	fmt.Println(tab, "  Not After   :", e.cert.NotAfter)
	fmt.Println(tab, "Key Usage     :", printKeyUsage(e.cert.KeyUsage))
	fmt.Println(tab, "Ext Key Usage :", printExtKeyUsage(e.cert))

	if temp := printAltNames(e.cert); temp != "" {
		fmt.Println(tab, "Alt Names     :", temp)
	}
	fmt.Println(tab, "CA            :", e.cert.IsCA)

	if e.verified == nil {
		if selfsigned := isSelfSignedRoot(e.cert); selfsigned {
			fmt.Println(tab, "Self signed   :", isSelfSignedRoot(e.cert))
		} else {
			fmt.Println(tab, "Verified      : true")
		}
	} else {
		fmt.Println(tab, "Verified      : false,", e.verified)
	}
	fmt.Println(tab, "Source        :", e.Source)
	fmt.Println()
}

func printName(val pkix.Name) string {
	var names []string
	for _, v := range val.Country {
		names = append(names, "C = "+v)
	}
	for _, v := range val.Organization {
		names = append(names, "O = "+v)
	}
	for _, v := range val.OrganizationalUnit {
		names = append(names, "OU = "+v)
	}
	for _, v := range val.Locality {
		names = append(names, "L = "+v)
	}
	for _, v := range val.Province {
		names = append(names, "P = "+v)
	}
	for _, v := range val.StreetAddress {
		names = append(names, "SA = "+v)
	}
	if val.SerialNumber != "" {
		names = append(names, "SN = "+val.SerialNumber)
	}
	if val.CommonName != "" {
		names = append(names, "CN = "+val.CommonName)
	}
	return strings.Join(names, ", ")
}

func printAltNames(cert *x509.Certificate) string {
	var names []string
	for _, v := range cert.DNSNames {
		names = append(names, "DNS:"+v)
	}
	for _, v := range cert.EmailAddresses {
		names = append(names, "EMAIL:"+v)
	}
	for _, v := range cert.IPAddresses {
		names = append(names, "IP:"+string(v))
	}
	for _, v := range cert.URIs {
		names = append(names, "URI:"+v.RawQuery)
	}
	return strings.Join(names, ", ")
}

func printKeyUsage(val x509.KeyUsage) string {
	var names []string
	if val&x509.KeyUsageDigitalSignature > 0 {
		names = append(names, "Digital Signiture")
	}
	if val&x509.KeyUsageContentCommitment > 0 {
		names = append(names, "Content Commitment")
	}
	if val&x509.KeyUsageKeyEncipherment > 0 {
		names = append(names, "Key Encipherment")
	}
	if val&x509.KeyUsageDataEncipherment > 0 {
		names = append(names, "Data Encipherment")
	}
	if val&x509.KeyUsageKeyAgreement > 0 {
		names = append(names, "Key Agreement")
	}
	if val&x509.KeyUsageCertSign > 0 {
		names = append(names, "Cert Sign")
	}
	if val&x509.KeyUsageCRLSign > 0 {
		names = append(names, "CRL Sign")
	}
	if val&x509.KeyUsageEncipherOnly > 0 {
		names = append(names, "Enciper Only")
	}
	if val&x509.KeyUsageDecipherOnly > 0 {
		names = append(names, "Decipher Only")
	}
	return strings.Join(names, ", ")
}

func printExtKeyUsage(cert *x509.Certificate) string {
	var names []string
	for _, v := range cert.ExtKeyUsage {
		switch v {
		case x509.ExtKeyUsageAny:
			names = append(names, "Any")
		case x509.ExtKeyUsageServerAuth:
			names = append(names, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			names = append(names, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			names = append(names, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			names = append(names, "Email Protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			names = append(names, "IPSEC End System")
		case x509.ExtKeyUsageIPSECTunnel:
			names = append(names, "IPSEC Tunnel")
		case x509.ExtKeyUsageIPSECUser:
			names = append(names, "IPSEC User")
		case x509.ExtKeyUsageTimeStamping:
			names = append(names, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			names = append(names, "OCSP Signing")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			names = append(names, "Microsoft Server Gated Crypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			names = append(names, "Netscape Server Gated Crypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			names = append(names, "Microsoft Commercial Code Signing")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			names = append(names, "Microsoft Kernel Code Signing")
		}
	}
	names = append(names, printUnknownExtKeyUsage(cert.UnknownExtKeyUsage))
	return strings.Join(names, ", ")
}
func printUnknownExtKeyUsage(val []asn1.ObjectIdentifier) string {
	var names []string
	for _, v := range val {
		names = append(names, v.String())
	}
	return strings.Join(names, ", ")
}

func encodeHex(val []byte) string {
	var names []string
	for _, v := range val {
		names = append(names, hex.EncodeToString([]byte{v}))
	}
	return strings.Join(names, ":")
}
