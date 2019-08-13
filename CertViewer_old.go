//+build ignore

package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"

	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	opts         x509.VerifyOptions
	pool         *x509.CertPool
	certlist     []*x509.Certificate
	verifiedlist map[*x509.Certificate][][]*x509.Certificate
	blocklist    []*pem.Block
)

type entry struct {
	cert   *x509.Certificate
	source string
	chain  [][]*x509.Certificate
}

const (
	//TABSIZE for output
	TABSIZE = 4
)

func main() {
	var (
		name = kingpin.Arg("name", "filename").Required().String()
	)

	kingpin.Version("0.0.1")
	kingpin.Parse()

	pool = x509.NewCertPool()
	certPEM, err := readFile(*name)
	if err != nil {
		log.Fatal("[ERROR] ", err)
	}
	verifiedlist = make(map[*x509.Certificate][][]*x509.Certificate)

	//decode
	for {
		block, rest := decode(certPEM)
		if block == nil {
			break
		}
		blocklist = append(blocklist, block)
		certPEM = rest
	}
	if certPEM == nil {
		log.Fatal("no certificates to check") // description ????
	}

	//parse
	for _, block := range blocklist {
		cert, err := x509.ParseCertificate(block.Bytes) // does not remove duplicates :thinking:
		if err != nil {
			log.Fatal("[ERROR] ", err)
		}
		fmt.Println("[printf DEBUG] Parsed Certificate!")
		fmt.Println(cert) // to change
		//appendunique(cert)
	}

	verifyallcerts()

	printCerts()
}

func decode(certPEM []byte) (block *pem.Block, rest []byte) {
	block, rest = pem.Decode(certPEM)
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE") {
		fmt.Println("[printf DEBUG] Skiped Block")
		return
	}
	fmt.Println("[printf DEBUG] Decoded PEM block!")
	return
}

func readFile(name string) ([]byte, error) {
	var certPEM []byte
	file, err := os.Open(name)
	if err != nil {
		//return nil, errors.Wrapf(err, "failed to open file %q", name)
		log.Fatal("[ERROR] no such file or directory")
	}
	defer file.Close()
	fmt.Println("[printf DEBUG] Opened File!")

	fileinfo, err := file.Stat()
	if err != nil {
		fmt.Println("[ERROR] ", err)
		return nil, err
	}
	filesize := fileinfo.Size()

	certPEM = make([]byte, filesize)
	for n := 1; n != 0; {
		n, err = file.Read(certPEM)
		if err != nil && n != 0 {
			log.Fatal("[ERROR] ", err)
		}
	}
	fmt.Println("[printf DEBUG] Read File!")
	return certPEM, nil
}

func verify(cert *x509.Certificate) bool {
	opts = x509.VerifyOptions{
		Intermediates: pool,
	}
	chain, err := cert.Verify(opts)
	if err != nil {
		return false
		// return false and to get reverified later
	}
	pool.AddCert(cert)
	verifiedlist[cert] = chain
	fmt.Println("[printf DEBUG] Verified Certificate!")
	return true
}

func verifyallcerts() {
	allverified := false
	count, lastcount := 0, -1
	for count != lastcount && !allverified {
		lastcount = count

		for iter := len(certlist) - 1; iter >= 0; iter-- {
			if verifiedlist[certlist[iter]] == nil {
				if verify(certlist[iter]) {
					count++
					allverified = (count == len(certlist))
				}
			}
		}
	}
	if count == lastcount {
		log.Println("[ERROR] could not finish chain, because it is not a verified certificate")
	}
}

func verifyallcerts2() {
	//redo this
	seen := make(map[string]bool)
	tasks := certlist
	for len(tasks) > 0 {
		var cert *x509.Certificate
		cert, tasks = tasks[0], tasks[1:]
		if seen[cert] {
			continue
		}
		// verify cert
		x := cert
		tasks = append(tasks, x)
	}
}

func printCerts() error {
	fmt.Println()
	for _, cert := range certlist {
		printCert(cert, 0)
		for _, chainval := range verifiedlist[cert] {
			for certidx, certval := range chainval {
				if certval != cert {
					printCert(certval, certidx)
				}
			}
		}
	}
	return nil
}

func printCert(cert *x509.Certificate, tabcount int) {
	tab := strings.Repeat(" ", tabcount*TABSIZE)
	fmt.Print(tab, "Subject    : ", cert.Subject.CommonName, "\n")
	fmt.Print(tab, "Issued by  : ", cert.Issuer.CommonName, "\n")
	fmt.Print(tab, "Valid since: ", cert.NotBefore, "\n")
	fmt.Print(tab, "Valid till : ", cert.NotAfter, "\n")
	fmt.Print(tab, "CA         : ", cert.IsCA, "\n")
	fmt.Print(tab, "Version    : ", cert.Version, "\n")
	fmt.Print(tab, "IPs        : ", cert.IPAddresses, "\n")
	fmt.Print(tab, "Sign Algo  : ", cert.SignatureAlgorithm, "\n")
	fmt.Print(tab, "Verified   : ", (verifiedlist[cert] != nil), "\n")
	fmt.Println()
}
