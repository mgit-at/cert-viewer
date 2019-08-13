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
		name = kingpin.Arg("name", "filename").Required().String()
		//usesysroot = kingpin.Flag("Use Root", "Should Sysroot be used").Default(true).Bool()
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

	err = certlist.verifyAllCerts(pool)
	if err != nil {
		return err
	}

	certlist.printCerts()

	return nil

}

func verify(cert *x509.Certificate, pool *x509.CertPool) ([][]*x509.Certificate, error) {
	//if usesysroot {
	opts := x509.VerifyOptions{
		Intermediates: pool,
	}
	//} else {
	//	opts := x509.VerifyOptions{
	//		Intermediates: pool,
	//		Roots:         x509.NewCertPool(),
	//	}
	//}
	chain, err := cert.Verify(opts)
	if err != nil {
		return nil, err
	}
	pool.AddCert(cert)
	fmt.Println("[printf DEBUG] Verified Certificate!")
	return chain, nil
}

func (e entrylist) verifyAllCerts(pool *x509.CertPool) (err error) {
	wip, notdone := true, true
	for wip && notdone {
		wip, notdone = false, false
		for idx, curentry := range e {
			if curentry.chain == nil {
				curentry.chain, err = verify(curentry.cert, pool)
				if err == nil {
					wip = true
				}
				curentry.verified = err
			}
			notdone = notdone || (curentry.verified != nil)
			e[idx] = curentry
		}
	}
	return
}

func (e entrylist) verifyAllCerts2(pool *x509.CertPool) (err error) {

	tasks := e
	oldlen := len(tasks) + 1
	for len(tasks) > 0 && len(tasks) != oldlen {
		oldlen = len(tasks)
		var curtask entry
		curtask, tasks = tasks[0], tasks[1:]

		chain, err := verify(curtask.cert, pool)
		if err != nil {
			curtask.verified = err
			tasks = append(tasks, curtask)
		} else {
			curtask.verified = nil
		}
		curtask.chain = chain
	}
	return
}

func parse(blocklist []*pem.Block, name string) (entrylist, error) {
	var el entrylist
	for i, block := range blocklist {
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		el = append(el, entry{c, (name + " | Certificate: " + strconv.Itoa(i)), nil, nil})

		fmt.Println("[printf DEBUG] Parsed Certificate!")
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
			fmt.Println("[printf DEBUG] Skiped Block")
			continue
		}
		fmt.Println("[printf DEBUG] Decoded PEM block!")
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
	fmt.Println("[printf DEBUG] Opened File!")

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
	fmt.Println("[printf DEBUG] Read File!")
	return certPEM, nil
}

func (e entrylist) printCerts() (err error) {
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
	return
}

func printEntry(e entry, tabcount int) {
	tab := strings.Repeat(" ", tabcount*4)
	printName(e.cert.Subject)
	fmt.Print(tab, "Subject       : ", printName(e.cert.Subject), "\n")
	fmt.Print(tab, "Version       : ", e.cert.Version, "\n")
	fmt.Print(tab, "Issued by     : ", printName(e.cert.Issuer), "\n")
	fmt.Print(tab, "Valid since   : ", e.cert.NotBefore, "\n")
	fmt.Print(tab, "Valid till    : ", e.cert.NotAfter, "\n")
	fmt.Print(tab, "Key Usage     : ", e.cert.KeyUsage, "\n")
	fmt.Print(tab, "Ext Key Usage : ", e.cert.ExtKeyUsage, "\n")
	fmt.Print(tab, "CA            : ", e.cert.IsCA, "\n")

	if temp := printAltNames(e.cert); temp != "" {
		fmt.Print(tab, "Alt Names     : ", temp, "\n")
	}

	fmt.Print(tab, "Sign Algo     : ", e.cert.SignatureAlgorithm, "\n")

	if e.verified == nil {
		fmt.Print(tab, "Verified      : true\n")
	} else {
		fmt.Print(tab, "Verified      : ", e.verified, "\n")
	}

	fmt.Print(tab, "Source        : ", e.source, "\n")
	fmt.Println()
}

func printName(val pkix.Name) (ret string) {
	ret = ""
	for _, v := range val.Country {
		ret = ret + "C: " + v + " "
	}
	for _, v := range val.Organization {
		ret = ret + "O: " + v + " "
	}
	for _, v := range val.OrganizationalUnit {
		ret = ret + "OU: " + v + " "
	}
	for _, v := range val.Locality {
		ret = ret + "L: " + v + " "
	}
	for _, v := range val.Province {
		ret = ret + "P: " + v + " "
	}
	for _, v := range val.StreetAddress {
		ret = ret + "SA: " + v + " "
	}
	if val.SerialNumber != "" {
		ret = ret + "SN: " + val.SerialNumber + " "
	}
	if val.CommonName != "" {
		ret = ret + "CN: " + val.CommonName + " "
	}
	return
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

func printExtKeyUsage(val int) string {
	switch val {
	case 0:
		return "Any"
	case 1:
		return "Server authentication"
	case 2:
		return "Any"
	case 3:
		return "Any"
	case 4:
		return "Any"
	case 5:
		return "Any"
	case 6:
		return "Any"
	case 7:
		return "Any"
	case 8:
		return "Any"
	case 9:
		return "Any"
	case 10:
		return "Any"
	case 11:
		return "Any"
	default:
		return "Any"
	}
}

//[] output:
//[] X509v3 Key Usage: critical
//[] X509v3 Extended Key Usage:
//
//[X]X509v3 Subject Alternative Name:
//
//
//[] Parameter
//[] ignore sys root certs
//
//[] verified reasoning
