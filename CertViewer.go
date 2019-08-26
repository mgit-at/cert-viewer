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
upcoming features:
[X] multiple files
[X] split source into 2 / source and sourcepos
[ ] json output
[X] remove subchain output
*/

type entry struct {
	Cert      *x509.Certificate `json:"certificate"`
	Source    string            `json:"source"`
	SourcePos int               `json:"sourceposition"`
	Verified  error             `json:"verify error"`
	chain     [][]*x509.Certificate
	printed   bool
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
		usefolder  = kingpin.Flag("usefolder", "Should the directory be used isntead of a filename").Default("false").Bool()
	)
	kingpin.Version("0.0.1")
	kingpin.Parse()

	var certlist entrylist
	if *usefolder {
		var err error
		certlist, err = runfolder(*name)
		if err != nil {
			return err
		}
	} else {
		certPEM, err := ioutil.ReadFile(*name)
		if err != nil {
			return errors.Wrapf(err, "failed to read file %q", *name)
		}

		blocklist, err := decode(certPEM)
		if err != nil {
			return errors.Wrap(err, "failed to decode PEM")
		}
		certlist, err = parse(blocklist, *name)
		if err != nil {
			return errors.Wrap(err, "failed to parse")
		}
	}

	if err := certlist.verifyAllCerts(*usesysroot); err != nil {
		return errors.Wrap(err, "failed to verify")
	}

	chain, err := certlist.mergeChain()
	if err != nil {
		return errors.Wrap(err, "failed to parse")
	}

	//return errors.Wrap(err, "failed to parse")
	newlist, err := certlist.printChain(chain)
	if err != nil {
		return errors.Wrap(err, "failed to print")
	}

	data, err := json.MarshalIndent(newlist, "", "  ")
	if err != nil {
		return errors.Wrap(err, "failed to convert to json")
	}
	ioutil.WriteFile("/home/daniel/Schreibtisch/testfile.json", data, os.FileMode(0777))

	return nil
}

func runfolder(name string) (entrylist, error) {
	files, err := ioutil.ReadDir(name)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read directory %q", name)
	}
	var filelist []os.FileInfo
	for _, f := range files {
		if strings.Contains(f.Name(), ".crt") || strings.Contains(f.Name(), ".cert") || strings.Contains(f.Name(), ".pem") {
			filelist = append(filelist, f)
		}
	}
	var el entrylist
	for _, f := range filelist {
		fname := name + "/" + f.Name()

		certpem, err := ioutil.ReadFile(fname)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read file %q", f.Name())
		}
		nblocklist, err := decode(certpem)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode PEM")
		}

		certlist, err := parse(nblocklist, fname)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse")
		}

		el = append(el, certlist...)
	}
	return el, nil
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
			Cert:      c,
			Source:    name,
			SourcePos: i,
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
			curentry.chain, curentry.Verified = verify(curentry, pool, roots)
			switch errors.Cause(curentry.Verified).(type) {
			case x509.SystemRootsError:
				return curentry.Verified
			case nil:
				wip = true
			}
			notdone = notdone || (curentry.Verified != nil)
			el[idx] = curentry
		}
	}
	return nil
}

func verify(e entry, pool *x509.CertPool, root *x509.CertPool) ([][]*x509.Certificate, error) {
	if isSelfSignedRoot(e.Cert) {
		root.AddCert(e.Cert)
	}
	opts := x509.VerifyOptions{
		Intermediates: pool,
		Roots:         root,
	}

	chain, err := e.Cert.Verify(opts)
	if err != nil {
		return nil, err
	}
	pool.AddCert(e.Cert)
	return chain, nil
}

func (el entrylist) mergeChain() ([][]*x509.Certificate, error) {
	type chainstruct struct {
		chain    []*x509.Certificate
		subchain bool
	}
	var comchain []chainstruct
	for _, v := range el {
		for _, c := range v.chain {
			comchain = append(comchain, chainstruct{chain: c, subchain: false})
		}
	}

	var redchain [][]*x509.Certificate
	if len(comchain) > 1 {
		for _, v1 := range comchain {
			for _, v2 := range comchain {
				if isSubchain(v2.chain, v1.chain) {
					v1.subchain = true
					break
				}
			}
			if !v1.subchain {
				redchain = append(redchain, v1.chain)
			}
		}
	}
	return redchain, nil
}

func isSelfSignedRoot(cert *x509.Certificate) bool {
	if cert.AuthorityKeyId != nil {
		return string(cert.AuthorityKeyId) == string(cert.SubjectKeyId) && cert.IsCA
	}
	return cert.Subject.String() == cert.Issuer.String() && cert.IsCA
}

func compareCert(cert1, cert2 *x509.Certificate) bool {
	return string(cert2.SubjectKeyId) == string(cert1.SubjectKeyId)
}

func isSubchain(mainchain, subchain []*x509.Certificate) bool {
	if len(mainchain) <= len(subchain) {
		return false
	}
	dif := len(mainchain) - len(subchain)

	for i := dif; i < len(mainchain); i++ {
		if !compareCert(mainchain[i], subchain[i-dif]) {
			return false
		}
	}

	return true
}

func (el entrylist) printChain(chain [][]*x509.Certificate) (entrylist, error) {
	var printedlist entrylist
	for i, chainval := range chain {
		if i > 0 {
			fmt.Println(strings.Repeat("=", 100))
			fmt.Println()
		}
		for certidx, certval := range chainval {
			certentry := entry{
				Cert:      certval,
				Source:    "Certificate from System Roots ",
				SourcePos: -1,
			}

			for i, e := range el {
				if compareCert(e.Cert, certval) {
					el[i].printed = true
					certentry = e
				}
			}

			if certidx > 0 {
				fmt.Println(strings.Repeat("- ", 50))
			}
			printEntry(certentry, certidx)
			printedlist = append(printedlist, certentry)
		}
	}

	for _, e := range el {
		if !e.printed {
			if len(printedlist) > 0 {
				fmt.Println(strings.Repeat("=", 100))
				fmt.Println()
			}
			printEntry(e, 0)
			printedlist = append(printedlist, e)
		}
	}
	return printedlist, nil

}

func printEntry(e entry, tabcount int) {
	tab := strings.Repeat(" ", tabcount*4)
	printName(e.Cert.Subject)
	fmt.Println(tab, "Subject       :", printName(e.Cert.Subject))
	fmt.Println(tab, "Version       :", e.Cert.Version)
	fmt.Println(tab, "Serial Number :", encodeHex(e.Cert.SerialNumber.Bytes()))
	fmt.Println(tab, "Sign Algo     :", e.Cert.SignatureAlgorithm)
	fmt.Println(tab, "Issuer        :", printName(e.Cert.Issuer))
	fmt.Println(tab, "Validity:")
	fmt.Println(tab, "  Not Before  :", e.Cert.NotBefore)
	fmt.Println(tab, "  Not After   :", e.Cert.NotAfter)
	fmt.Println(tab, "Key Usage     :", printKeyUsage(e.Cert.KeyUsage))
	fmt.Println(tab, "Ext Key Usage :", printExtKeyUsage(e.Cert))

	if temp := printAltNames(e.Cert); temp != "" {
		fmt.Println(tab, "Alt Names     :", temp)
	}
	fmt.Println(tab, "CA            :", e.Cert.IsCA)

	if e.Verified == nil {
		if selfsigned := isSelfSignedRoot(e.Cert); selfsigned {
			fmt.Println(tab, "Verified      : true, self signed")
		} else {
			fmt.Println(tab, "Verified      : true")
		}
	} else {
		fmt.Println(tab, "Verified      : false,", e.Verified)
	}
	if e.SourcePos < 0 {
		fmt.Println(tab, "Source        :", e.Source)
	} else {
		fmt.Println(tab, "Source        :", e.Source+" | Certificate: "+strconv.Itoa(e.SourcePos))
	}
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
