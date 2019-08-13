package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"gopkg.in/alecthomas/kingpin.v2"
)

func main() {
	err := run()
	if err != nil {
		log.Fatal("[ERROR] ", err)
	}
}

type entry struct {
	cert     *x509.Certificate
	source   string
	chain    [][]*x509.Certificate
	verified error
}

type entrylist []entry

func run() error {

	var (
		name       = kingpin.Arg("name", "filename").Required().String()
		usesysroot = kingpin.Flag("usesysroot", "Should Sysroot be used").Default("true").Bool()
	)

	kingpin.Version("0.0.1")
	kingpin.Parse()

	certPEM, err := readFile(*name)
	if err != nil {
		return err
	}

	blocklist, err := decode(certPEM)
	if err != nil {
		return err
	}

	certlist, err := parse(blocklist, *name)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()

	certlist.verifyAllCerts(pool, *usesysroot)

	certlist.printCerts()

	return nil

}

func verify(cert *x509.Certificate, pool *x509.CertPool, usesysroot bool) ([][]*x509.Certificate, error) {
	var opts x509.VerifyOptions
	if usesysroot {
		opts = x509.VerifyOptions{
			Intermediates: pool,
		}
	} else {
		opts = x509.VerifyOptions{
			Intermediates: pool,
			Roots:         x509.NewCertPool(),
		}
	}
	chain, err := cert.Verify(opts)
	if err != nil {
		return nil, err
	}
	pool.AddCert(cert)
	return chain, nil
}

func (e entrylist) verifyAllCerts(pool *x509.CertPool, usesysroot bool) {
	wip, notdone := true, true
	for wip && notdone {
		wip, notdone = false, false
		for idx, curentry := range e {
			if curentry.chain != nil {
				continue
			}
			curentry.chain, curentry.verified = verify(curentry.cert, pool, usesysroot)
			if curentry.verified == nil {
				wip = true
			}
			e[idx] = curentry
			notdone = notdone || (curentry.verified != nil)
		}
	}
}

/*func (e entrylist) verifyAllCerts2(pool *x509.CertPool, usesysroot bool) {
	tasks := e
	oldlen := len(tasks) + 1
	for len(tasks) > 0 && len(tasks) != oldlen {
		oldlen = len(tasks)
		var curtask entry
		curtask, tasks = tasks[0], tasks[1:]

		curtask.chain, curtask.verified := verify(curtask.cert, pool, usesysroot)
		if err != nil {
			tasks = append(tasks, curtask)
		}
	}
}*/

func parse(blocklist []*pem.Block, name string) (entrylist, error) {
	var el entrylist
	for i, block := range blocklist {
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		el = append(el, entry{c, (name + " | Certificate: " + strconv.Itoa(i)), nil, nil})
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
	if blocklist == nil {
		return nil, errors.New("no certificates to check")
	}
	return blocklist, nil
}

func readFile(name string) ([]byte, error) {
	var certPEM []byte
	file, err := os.Open(name)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open file %q", name)
	}
	defer file.Close()

	fileinfo, err := file.Stat()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open file %q", name)
	}
	filesize := fileinfo.Size()

	certPEM = make([]byte, filesize)
	for n := 1; n != 0; {
		n, err = file.Read(certPEM)
		if err != nil && n != 0 {
			return nil, errors.Wrapf(err, "failed to open file %q", name)
		}
	}
	return certPEM, nil
}

func (e entrylist) printCerts() {
	//TODO
	fmt.Println()
	for _, curentry := range e {
		printEntry(curentry, 0)
		for _, chainval := range curentry.chain {
			for certidx, certval := range chainval {
				if certval != curentry.cert {
					// string together chain source
					cert := entry{certval, "Chain off: " + curentry.source, nil, nil}
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
	fmt.Println(tab, "Issuer        :", printName(e.cert.Issuer))
	fmt.Println(tab, "Validity:")
	fmt.Println(tab, "  Not Before  :", e.cert.NotBefore)
	fmt.Println(tab, "  Not After   :", e.cert.NotAfter)
	fmt.Println(tab, "Key Usage     :", printKeyUsage(e.cert.KeyUsage))
	fmt.Println(tab, "Ext Key Usage :", printExtKeyUsage(e.cert.ExtKeyUsage))

	fmt.Println(tab, "CA            :", e.cert.IsCA)

	if temp := printAltNames(e.cert); temp != "" {
		fmt.Println(tab, "Alt Names     :", temp)
	}

	fmt.Println(tab, "Sign Algo     :", e.cert.SignatureAlgorithm)

	if e.verified == nil {
		fmt.Println(tab, "Verified      : true")
	} else {
		fmt.Println(tab, "Verified      : false,", e.verified)
	}

	fmt.Println(tab, "Source        :", e.source)
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

func printExtKeyUsage(val []x509.ExtKeyUsage) string {
	var names []string
	for _, v := range val {
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
	return strings.Join(names, ", ")
}

//[] output:
//[X] X509v3 Key Usage: critical
//[] X509v3 Extended Key Usage:
//
//[X]X509v3 Subject Alternative Name:
//
//
//[X] Parameter
//[X] ignore sys root certs
//
//[] verified reasoning