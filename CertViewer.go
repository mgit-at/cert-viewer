package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"gopkg.in/alecthomas/kingpin.v2"
)

/*
[X]json flag for commandline
[X]multiple args instead of flag
[X]automatic detection of directory
[X]path/filepath/.walk
[ ]Source as list
*/

type entry struct {
	Cert      *x509.Certificate `json:"certificate"`
	Source    string            `json:"source"`
	Verified  error             `json:"verify error"`
	sourcePos int
	chain     [][]*x509.Certificate
	printed   bool
}

type entrylist []entry

type validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type jsonentry struct {
	Subject      pkix.Name `json:"subject"`
	Version      int       `json:"version"`
	Serialnumber string    `json:"serialnumber"`
	SignAlgo     string    `json:"signature algorithm"`
	Issuer       pkix.Name `json:"issuer"`
	Validity     validity  `json:"validity"`
	KeyUsage     []string  `json:"key usage"`
	ExtKeyUsage  []string  `json:"extended key usage"`
	AltNames     []string  `json:"alternative names"`
	CA           bool      `json:"ca"`
	Verified     string    `json:"verified"`
	Source       string    `json:"source"`
}

func main() {
	if err := run(); err != nil {
		log.Fatal("[ERROR] ", err)
	}
}

func run() error {
	var (
		names      = kingpin.Arg("name", "filename").Required().Strings()
		usesysroot = kingpin.Flag("usesysroot", "Should Sysroot be used").Default("true").Bool()
		jsonflag   = kingpin.Flag("json", "Should json syntax be used").Bool()
	)
	kingpin.Version("0.0.1")
	kingpin.Parse()

	var certlist entrylist
	for _, name := range *names {
		err := filepath.Walk(name, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return errors.Wrapf(err, "failed to read file %q", path)
			}
			if strings.Contains(info.Name(), ".crt") || strings.Contains(info.Name(), ".cert") || strings.Contains(info.Name(), ".pem") {
				certpem, err := ioutil.ReadFile(path)
				if err != nil {
					return errors.Wrapf(err, "failed to read file %q", path)
				}
				nblocklist, err := decode(certpem)
				if err != nil {
					return errors.Wrap(err, "failed to decode PEM")
				}

				list, err := parse(nblocklist, path)
				if err != nil {
					return errors.Wrap(err, "failed to parse")
				}
				certlist = append(certlist, list...)
			}
			return nil
		})
		if err != nil {
			return errors.Wrap(err, "failed to file walk")
		}
	}

	if err := certlist.verifyAllCerts(*usesysroot); err != nil {
		return errors.Wrap(err, "failed to verify")
	}

	chain, err := certlist.mergeChain()
	if err != nil {
		return errors.Wrap(err, "failed to parse")
	}

	if err = certlist.printChain(chain, *jsonflag); err != nil {
		return errors.Wrap(err, "failed to print")
	}

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
			Cert:      c,
			Source:    name,
			sourcePos: i,
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

	var reducedchain [][]*x509.Certificate
	for i1, v1 := range comchain {
		for i2, v2 := range comchain {
			if i1 != i2 && !v2.subchain {
				if isSubchain(v2.chain, v1.chain) {
					v1.subchain = true
					break
				}
			}
		}
		if !v1.subchain {
			reducedchain = append(reducedchain, v1.chain)
		}
	}
	return reducedchain, nil
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

	for i := 0; i < len(subchain); i++ {
		if !compareCert(mainchain[len(mainchain)-i-1], subchain[len(subchain)-i-1]) {
			return false
		}
	}

	return true
}

func (el entrylist) printChain(chain [][]*x509.Certificate, jsonflag bool) error {
	notfirstprint := true

	for i, chainval := range chain {
		if i > 0 && !jsonflag {
			if !jsonflag {
				fmt.Println(strings.Repeat("=", 100))
				fmt.Println()
				notfirstprint = false
			} else {
				fmt.Print(",")
			}
		}
		for certidx, certval := range chainval {
			certentry := entry{
				Cert:      certval,
				Source:    "Certificate from System Roots ",
				sourcePos: -1,
			}

			for i, e := range el {
				if compareCert(e.Cert, certval) {
					el[i].printed = true
					certentry = e
				}
			}

			if certidx > 0 {
				if !jsonflag {
					fmt.Println(strings.Repeat("- ", 50))
				} else {
					fmt.Print(",")
				}
			}
			if err := printSingle(certentry, certidx, jsonflag); err != nil {
				return err
			}
		}
	}

	for _, e := range el {
		if !e.printed {
			if notfirstprint && !jsonflag {
				if jsonflag {
					fmt.Println(strings.Repeat("=", 100))
					fmt.Println()
				} else {
					fmt.Print(",")
				}
			}

			if err := printSingle(e, 0, jsonflag); err != nil {
				return err
			}
		}
	}
	return nil

}

func printSingle(e entry, tabcount int, jsonflag bool) error {
	jsn, err := initJSON(e)
	if err != nil {
		return err
	}
	if !jsonflag {
		printEntry(jsn, tabcount)
	} else {
		data, err := json.MarshalIndent(jsn, "", "  ")
		if err != nil {
			return errors.Wrap(err, "failed to convert to json")
		}
		fmt.Println(string(data))

	}

	return nil
}
func initJSON(e entry) (jsonentry, error) {
	jsn := jsonentry{
		Subject:  e.Cert.Subject,
		Version:  e.Cert.Version,
		SignAlgo: e.Cert.SignatureAlgorithm.String(),
		Issuer:   e.Cert.Issuer,
		Validity: validity{
			NotBefore: e.Cert.NotBefore,
			NotAfter:  e.Cert.NotAfter},
		CA: e.Cert.IsCA,
	}
	jsn.Serialnumber = encodeHex(e.Cert.SerialNumber.Bytes())

	jsn.printKeyUsage(e.Cert.KeyUsage)
	jsn.printExtKeyUsage(e.Cert)
	jsn.printAltNames(e.Cert)

	if e.Verified == nil {
		if selfsigned := isSelfSignedRoot(e.Cert); selfsigned {
			jsn.Verified = "true, self signed"
		} else {
			jsn.Verified = "true"
		}
	} else {
		jsn.Verified = "false," + e.Verified.Error()
	}

	jsn.Source = e.Source
	if e.sourcePos >= 0 {
		jsn.Source += " | Certificate: " + strconv.Itoa(e.sourcePos)
	}

	return jsn, nil
}

func printEntry(jsn jsonentry, tabcount int) error {

	tab := strings.Repeat(" ", tabcount*4)

	fmt.Println(tab, "Subject       :", printName(jsn.Subject))
	fmt.Println(tab, "Version       :", jsn.Version)
	fmt.Println(tab, "Serial Number :", jsn.Serialnumber)
	fmt.Println(tab, "Sign Algo     :", jsn.SignAlgo)
	fmt.Println(tab, "Issuer        :", printName(jsn.Issuer))
	fmt.Println(tab, "Validity:")
	fmt.Println(tab, "  Not Before  :", jsn.Validity.NotBefore)
	fmt.Println(tab, "  Not After   :", jsn.Validity.NotAfter)
	fmt.Println(tab, "Key Usage     :", strings.Join(jsn.ExtKeyUsage, ", "))
	fmt.Println(tab, "Ext Key Usage :", strings.Join(jsn.KeyUsage, ", "))
	fmt.Println(tab, "Alt Names     :", strings.Join(jsn.AltNames, ", "))
	fmt.Println(tab, "CA            :", jsn.CA)
	fmt.Println(tab, "Verified      :", jsn.Verified)
	fmt.Println(tab, "Source        :", jsn.Source)
	fmt.Println()

	return nil
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

func (je *jsonentry) printAltNames(cert *x509.Certificate) {
	for _, v := range cert.DNSNames {
		je.AltNames = append(je.AltNames, "DNS:"+v)
	}
	for _, v := range cert.EmailAddresses {
		je.AltNames = append(je.AltNames, "EMAIL:"+v)
	}
	for _, v := range cert.IPAddresses {
		je.AltNames = append(je.AltNames, "IP:"+string(v))
	}
	for _, v := range cert.URIs {
		je.AltNames = append(je.AltNames, "URI:"+v.RawQuery)
	}
}

func (je *jsonentry) printKeyUsage(val x509.KeyUsage) {
	if val&x509.KeyUsageDigitalSignature > 0 {
		je.KeyUsage = append(je.KeyUsage, "Digital Signiture")
	}
	if val&x509.KeyUsageContentCommitment > 0 {
		je.KeyUsage = append(je.KeyUsage, "Content Commitment")
	}
	if val&x509.KeyUsageKeyEncipherment > 0 {
		je.KeyUsage = append(je.KeyUsage, "Key Encipherment")
	}
	if val&x509.KeyUsageDataEncipherment > 0 {
		je.KeyUsage = append(je.KeyUsage, "Data Encipherment")
	}
	if val&x509.KeyUsageKeyAgreement > 0 {
		je.KeyUsage = append(je.KeyUsage, "Key Agreement")
	}
	if val&x509.KeyUsageCertSign > 0 {
		je.KeyUsage = append(je.KeyUsage, "Cert Sign")
	}
	if val&x509.KeyUsageCRLSign > 0 {
		je.KeyUsage = append(je.KeyUsage, "CRL Sign")
	}
	if val&x509.KeyUsageEncipherOnly > 0 {
		je.KeyUsage = append(je.KeyUsage, "Enciper Only")
	}
	if val&x509.KeyUsageDecipherOnly > 0 {
		je.KeyUsage = append(je.KeyUsage, "Decipher Only")
	}
}

func (je *jsonentry) printExtKeyUsage(cert *x509.Certificate) {
	for _, v := range cert.ExtKeyUsage {
		switch v {
		case x509.ExtKeyUsageAny:
			je.ExtKeyUsage = append(je.ExtKeyUsage, "Any")
		case x509.ExtKeyUsageServerAuth:
			je.ExtKeyUsage = append(je.ExtKeyUsage, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			je.ExtKeyUsage = append(je.ExtKeyUsage, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			je.ExtKeyUsage = append(je.ExtKeyUsage, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			je.ExtKeyUsage = append(je.ExtKeyUsage, "Email Protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			je.ExtKeyUsage = append(je.ExtKeyUsage, "IPSEC End System")
		case x509.ExtKeyUsageIPSECTunnel:
			je.ExtKeyUsage = append(je.ExtKeyUsage, "IPSEC Tunnel")
		case x509.ExtKeyUsageIPSECUser:
			je.ExtKeyUsage = append(je.ExtKeyUsage, "IPSEC User")
		case x509.ExtKeyUsageTimeStamping:
			je.ExtKeyUsage = append(je.ExtKeyUsage, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			je.ExtKeyUsage = append(je.ExtKeyUsage, "OCSP Signing")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			je.ExtKeyUsage = append(je.ExtKeyUsage, "Microsoft Server Gated Crypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			je.ExtKeyUsage = append(je.ExtKeyUsage, "Netscape Server Gated Crypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			je.ExtKeyUsage = append(je.ExtKeyUsage, "Microsoft Commercial Code Signing")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			je.ExtKeyUsage = append(je.ExtKeyUsage, "Microsoft Kernel Code Signing")
		}
	}
	for _, v := range cert.UnknownExtKeyUsage {
		je.ExtKeyUsage = append(je.ExtKeyUsage, v.String())
	}
}

func encodeHex(val []byte) string {
	var names []string
	for _, v := range val {
		names = append(names, hex.EncodeToString([]byte{v}))
	}
	return strings.Join(names, ":")
}
