//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/alecthomas/kingpin.v2"
)

type entry struct {
	cert     *x509.Certificate
	source   []source
	verified error
	chain    [][]*x509.Certificate
	inChain  bool
}

type entryList []entry
type jsonList []jsonEntry

type validity struct {
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

type source struct {
	Name     string `json:"name"`
	Position int    `json:"position"`
}

type verifiedInfo struct {
	Status bool   `json:"status"`
	Info   string `json:"info"`
}

type jsonEntry struct {
	Subject        jsonName     `json:"subject"`
	Version        int          `json:"version"`
	SerialNumber   string       `json:"serialnumber"`
	SignAlgo       string       `json:"signature_algorithm"`
	Issuer         jsonName     `json:"issuer"`
	Validity       validity     `json:"validity"`
	KeyUsage       []string     `json:"key_usage"`
	ExtKeyUsage    []string     `json:"extended_key_usage"`
	AltNames       []string     `json:"alternative_names"`
	SubjectKeyID   string       `json:"subject_key_id"`
	AuthorityKeyID string       `json:"authority_key_id"`
	CA             bool         `json:"ca"`
	Verified       verifiedInfo `json:"verified"`
	Source         []source     `json:"source"`
	chaindepth     int
}
type jsonName struct {
	Country            []string `json:"country"`
	Organization       []string `json:"organization"`
	OrganizationalUnit []string `json:"organizational_unit"`
	Locality           []string `json:"locality"`
	Province           []string `json:"province"`
	StreetAddress      []string `json:"street_address"`
	PostalCode         []string `json:"postal_code"`
	SerialNumber       string   `json:"serial_number"`
	CommonName         string   `json:"common_name"`
}

func main() {
	if err := run(); err != nil {
		log.Fatal("[ERROR] ", err)
	}
}

func run() error {
	var (
		names          = kingpin.Arg("name", "filename and/or directory paths").Required().Strings()
		disablesysroot = kingpin.Flag("disablesysroot", "disable system root certificates from being used").Default("false").Bool()
		jsonflag       = kingpin.Flag("json", "enable JSON output").Bool()
	)
	kingpin.Parse()

	var certlist entryList
	for _, name := range *names {
		err := filepath.Walk(name, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return errors.Wrapf(err, "failed to read file %q", path)
			}
			if ext := strings.ToLower(filepath.Ext(info.Name())); ext == ".cert" || ext == ".crt" || ext == ".pem" {
				certpem, err := ioutil.ReadFile(path)
				if err != nil {
					return errors.Wrapf(err, "failed to read file %q", path)
				}
				nblocklist, err := decode(certpem)
				if err != nil {
					return errors.Wrap(err, "failed to decode PEM")
				}

				if err := certlist.parse(nblocklist, path); err != nil {
					return errors.Wrap(err, "failed to parse")
				}
			}
			return nil
		})
		if err != nil {
			return errors.Wrap(err, "failed to file walk")
		}
	}

	if err := certlist.verifyAllCerts(*disablesysroot); err != nil {
		return errors.Wrap(err, "failed to verify")
	}

	chain, err := certlist.mergeChain()
	if err != nil {
		return errors.Wrap(err, "failed to parse")
	}

	jl, err := certlist.initJSONList(chain)
	if err != nil {
		return errors.Wrap(err, "failed to initialize the JSON list")
	}

	if err = jl.printAll(*jsonflag); err != nil {
		return errors.Wrap(err, "failed to print")
	}

	return nil
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

func decode(certPEM []byte) ([]*pem.Block, error) {
	var blocklist []*pem.Block
	for {
		block, rest := pem.Decode(certPEM)
		certPEM = rest
		if block == nil {
			break
		}
		if !strings.Contains(block.Type, "CERTIFICATE") {
			continue
		}
		blocklist = append(blocklist, block)
	}
	if len(blocklist) == 0 {
		return nil, errors.New("No certificates to check")
	}
	return blocklist, nil
}

func (el *entryList) parse(blocklist []*pem.Block, filename string) error {
nextBlock:
	for i, block := range blocklist {
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.Wrapf(err, "failed to parse PEM block")
		}

		for idx, ent := range *el {
			if compareCert(c, ent.cert) {
				(*el)[idx].source = append((*el)[idx].source, source{filename, i + 1})
				continue nextBlock
			}
		}

		e := entry{
			cert:   c,
			source: []source{source{filename, i + 1}},
		}
		*el = append(*el, e)
	}
	return nil
}

func (el entryList) verifyAllCerts(disablesysroot bool) error {
	pool, roots := x509.NewCertPool(), x509.NewCertPool()
	if !disablesysroot {
		var err error
		if roots, err = x509.SystemCertPool(); err != nil {
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
			default:
				notdone = true
			}
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

func (el entryList) mergeChain() ([][]*x509.Certificate, error) {
	type chainStruct struct {
		chain    []*x509.Certificate
		subchain bool
	}
	var allchains []chainStruct
	for _, v := range el {
		for _, c := range v.chain {
			allchains = append(allchains, chainStruct{chain: c, subchain: false})
		}
	}

	var reducedchain [][]*x509.Certificate
	for i1, v1 := range allchains {
		for i2, v2 := range allchains {
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

func (el entryList) initJSONList(chainlist [][]*x509.Certificate) (jsonList, error) {
	var jl jsonList
	for _, chainval := range chainlist {
		for certidx, certval := range chainval {
			certentry, err := el.getEntryfromChain(certval)
			if err != nil {
				return nil, err
			}
			jsn := initJSON(certentry, certidx)
			jl = append(jl, jsn)
		}
	}

	for _, e := range el {
		if !e.inChain {
			jsn := initJSON(e, 0)
			jl = append(jl, jsn)
		}
	}
	return jl, nil
}

func (el entryList) getEntryfromChain(certval *x509.Certificate) (entry, error) {
	certentry := entry{
		cert:   certval,
		source: []source{source{Name: "Certificate from System Roots", Position: 0}},
	}

	for i, e := range el {
		if compareCert(e.cert, certval) {
			el[i].inChain = true
			certentry = e
			break
		}
	}
	return certentry, nil
}

func initJSON(e entry, chaindepth int) jsonEntry {
	return jsonEntry{
		Subject:        initName(e.cert.Subject),
		Version:        e.cert.Version,
		SignAlgo:       e.cert.SignatureAlgorithm.String(),
		Issuer:         initName(e.cert.Issuer),
		CA:             e.cert.IsCA,
		Source:         e.source,
		SerialNumber:   encodeHex(e.cert.SerialNumber.Bytes()),
		KeyUsage:       initKeyUsage(e.cert.KeyUsage),
		ExtKeyUsage:    initExtKeyUsage(e.cert),
		AltNames:       initAltNames(e.cert),
		SubjectKeyID:   encodeHex(e.cert.SubjectKeyId),
		AuthorityKeyID: encodeHex(e.cert.AuthorityKeyId),
		Verified:       initVerified(e),
		chaindepth:     chaindepth,
		Validity: validity{
			NotBefore: e.cert.NotBefore,
			NotAfter:  e.cert.NotAfter},
	}
}

func initName(name pkix.Name) jsonName {
	return jsonName{
		Country:            name.Country,
		Organization:       name.Organization,
		OrganizationalUnit: name.OrganizationalUnit,
		Locality:           name.Locality,
		Province:           name.Province,
		StreetAddress:      name.StreetAddress,
		PostalCode:         name.PostalCode,
		SerialNumber:       name.SerialNumber,
		CommonName:         name.CommonName,
	}
}

func initKeyUsage(val x509.KeyUsage) []string {
	var keyusage []string
	if val&x509.KeyUsageDigitalSignature > 0 {
		keyusage = append(keyusage, "Digital Signiture")
	}
	if val&x509.KeyUsageContentCommitment > 0 {
		keyusage = append(keyusage, "Content Commitment")
	}
	if val&x509.KeyUsageKeyEncipherment > 0 {
		keyusage = append(keyusage, "Key Encipherment")
	}
	if val&x509.KeyUsageDataEncipherment > 0 {
		keyusage = append(keyusage, "Data Encipherment")
	}
	if val&x509.KeyUsageKeyAgreement > 0 {
		keyusage = append(keyusage, "Key Agreement")
	}
	if val&x509.KeyUsageCertSign > 0 {
		keyusage = append(keyusage, "Cert Sign")
	}
	if val&x509.KeyUsageCRLSign > 0 {
		keyusage = append(keyusage, "CRL Sign")
	}
	if val&x509.KeyUsageEncipherOnly > 0 {
		keyusage = append(keyusage, "Enciper Only")
	}
	if val&x509.KeyUsageDecipherOnly > 0 {
		keyusage = append(keyusage, "Decipher Only")
	}
	return keyusage
}

func initExtKeyUsage(cert *x509.Certificate) []string {
	var extkeyusage []string
	for _, v := range cert.ExtKeyUsage {
		switch v {
		case x509.ExtKeyUsageAny:
			extkeyusage = append(extkeyusage, "Any")
		case x509.ExtKeyUsageServerAuth:
			extkeyusage = append(extkeyusage, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			extkeyusage = append(extkeyusage, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			extkeyusage = append(extkeyusage, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			extkeyusage = append(extkeyusage, "Email Protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			extkeyusage = append(extkeyusage, "IPSEC End System")
		case x509.ExtKeyUsageIPSECTunnel:
			extkeyusage = append(extkeyusage, "IPSEC Tunnel")
		case x509.ExtKeyUsageIPSECUser:
			extkeyusage = append(extkeyusage, "IPSEC User")
		case x509.ExtKeyUsageTimeStamping:
			extkeyusage = append(extkeyusage, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			extkeyusage = append(extkeyusage, "OCSP Signing")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			extkeyusage = append(extkeyusage, "Microsoft Server Gated Crypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			extkeyusage = append(extkeyusage, "Netscape Server Gated Crypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			extkeyusage = append(extkeyusage, "Microsoft Commercial Code Signing")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			extkeyusage = append(extkeyusage, "Microsoft Kernel Code Signing")
		}
	}
	for _, v := range cert.UnknownExtKeyUsage {
		extkeyusage = append(extkeyusage, v.String())
	}
	return extkeyusage
}

func initAltNames(cert *x509.Certificate) []string {
	var altnames []string
	for _, v := range cert.DNSNames {
		altnames = append(altnames, "DNS:"+v)
	}
	for _, v := range cert.EmailAddresses {
		altnames = append(altnames, "EMAIL:"+v)
	}
	for _, v := range cert.IPAddresses {
		altnames = append(altnames, "IP:"+string(v))
	}
	for _, v := range cert.URIs {
		altnames = append(altnames, "URI:"+v.RawQuery)
	}
	return altnames
}

func initVerified(e entry) verifiedInfo {
	if e.verified == nil {
		if isSelfSignedRoot(e.cert) {
			return verifiedInfo{true, "self signed"}
		}
		return verifiedInfo{true, ""}
	}
	return verifiedInfo{false, e.verified.Error()}
}

func (jl jsonList) printAll(jsonflag bool) error {
	if jsonflag {
		if err := jl.printJSON(); err != nil {
			return err
		}
	} else {
		jl.printInfo()
	}
	return nil
}

func (jl jsonList) printJSON() error {
	data, err := json.MarshalIndent(jl, "", "  ")
	if err != nil {
		return errors.Wrap(err, "failed to convert to json")
	}
	fmt.Println(string(data))
	return nil
}

func (jl jsonList) printInfo() {
	for i, jsn := range jl {
		if i > 0 {
			if jsn.chaindepth > 0 {
				fmt.Println(strings.Repeat("- ", 50))
			} else {
				fmt.Println(strings.Repeat("=", 100))
				fmt.Println()
			}
		}
		printEntry(jsn)
	}
}

func printEntry(jsn jsonEntry) {
	tab := strings.Repeat(" ", jsn.chaindepth*4)

	fmt.Println(tab, "Subject          :", formatName(jsn.Subject))
	fmt.Println(tab, "Version          :", jsn.Version)
	fmt.Println(tab, "Serial Number    :", jsn.SerialNumber)
	fmt.Println(tab, "Sign Algo        :", jsn.SignAlgo)
	fmt.Println(tab, "Issuer           :", formatName(jsn.Issuer))
	fmt.Println(tab, "Validity:")
	fmt.Println(tab, "  Not Before     :", jsn.Validity.NotBefore)
	fmt.Println(tab, "  Not After      :", jsn.Validity.NotAfter)
	fmt.Println(tab, "Key Usage        :", strings.Join(jsn.KeyUsage, ", "))
	fmt.Println(tab, "Ext Key Usage    :", strings.Join(jsn.ExtKeyUsage, ", "))
	fmt.Println(tab, "Alt Names        :", strings.Join(jsn.AltNames, ", "))
	fmt.Println(tab, "Subject Key ID   :", jsn.SubjectKeyID)
	fmt.Println(tab, "Authority Key ID :", jsn.AuthorityKeyID)
	fmt.Println(tab, "CA               :", jsn.CA)
	fmt.Println(tab, "Verified         :", formatVerified(jsn.Verified))
	printSources(jsn.Source, tab)
	fmt.Println()
	return
}

func formatVerified(vi verifiedInfo) string {
	if vi.Info != "" {
		return fmt.Sprintf("%v (%s)", vi.Status, vi.Info)
	}
	return fmt.Sprintf("%v", vi.Status)
}

func formatName(val jsonName) string {
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

func printSources(sources []source, tab string) {
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Name != sources[j].Name {
			return sources[i].Name < sources[j].Name
		}
		return sources[i].Position < sources[j].Position
	})
	for _, src := range sources {
		sourcetext := src.Name
		if src.Position > 0 {
			sourcetext += " | Certificate: " + strconv.Itoa(src.Position)
		}
		fmt.Println(tab, "Source           :", sourcetext)
	}
}

func encodeHex(val []byte) string {
	var names []string
	for _, v := range val {
		names = append(names, hex.EncodeToString([]byte{v}))
	}
	return strings.Join(names, ":")
}
