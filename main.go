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
	"bytes"
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

// entry holds a certificate with extra information like the source or its verification.
type entry struct {
	cert     *x509.Certificate
	source   []source
	verified error
	chain    [][]*x509.Certificate
	inChain  bool
}

type entryList []entry
type jsonList []jsonEntry

// validity holds from when till when a certificate is valid.
type validity struct {
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// source is a struct with information about filename and position in that file from the source.
type source struct {
	Name     string `json:"name"`
	Position int    `json:"position"`
}

// verifiedInfo holds status of the verification and some extra information,
// like error message and if it is self signed.
type verifiedInfo struct {
	Status bool   `json:"status"`
	Info   string `json:"info"`
}

// blockInfo holds a PEM Block, the source and eventual error
type blockInfo struct {
	block *pem.Block
	src   source
	err   error
}

// jsonEntry for a certificate entry.
type jsonEntry struct {
	Subject        jsonName     `json:"subject"`
	Version        int          `json:"version"`
	SerialNumber   string       `json:"serialnumber"`
	SignAlgo       string       `json:"signature_algorithm"`
	Issuer         jsonName     `json:"issuer"`
	Validity       validity     `json:"validity"`
	KeyUsage       []string     `json:"key_usage"`
	ExtKeyUsage    []string     `json:"extended_key_usage"`
	AltNames       jsonAltname  `json:"alternative_names"`
	SubjectKeyID   string       `json:"subject_key_id"`
	AuthorityKeyID string       `json:"authority_key_id"`
	CA             bool         `json:"ca"`
	Verified       verifiedInfo `json:"verified"`
	Source         []source     `json:"source"`
	chaindepth     int
}

// jsonname json struct for pkix name.
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

// jsonAltName string arrays for alternative certificate names
type jsonAltname struct {
	DNS   []string `json:"dns"`
	EMAIL []string `json:"email"`
	IP    []string `json:"ip"`
	URL   []string `json:"ulr"`
}

type decodeerror error

// main runs the run function and prints errors.
func main() {
	if err := run(); err != nil {
		log.Fatal("[ERROR] ", err)
	}
}

// run runs all step: reading, decoding, parsing, logic and printing.
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
			if ext := strings.ToLower(filepath.Ext(info.Name())); ext == ".cert" || ext == ".crt" || ext == ".pem" || ext == ".cer" {
				certpem, err := ioutil.ReadFile(path)
				if err != nil {
					return errors.Wrapf(err, "failed to read file %q", path)
				}
				nblocklist, err := decodePEM(certpem, path)
				if err != nil {
					return errors.Wrap(err, "failed to decode")
				}

				if err := certlist.parse(nblocklist); err != nil {
					switch err.(type) {
					case decodeerror:
						return errors.Wrap(err, "failed to decode")
					}
					return errors.Wrap(err, "failed to parse")
				}
				return nil
			}
			if !info.IsDir() {
				return fmt.Errorf("failed to read file %q (wrong extension)", path)
			}
			return nil
		})
		if err != nil {
			return errors.Wrap(err, "failed at file walk")
		}
	}

	if err := certlist.verifyAllCerts(*disablesysroot); err != nil {
		return errors.Wrap(err, "failed to verify")
	}

	chain := certlist.mergeChain()
	jl := certlist.initJSONList(chain)

	if err := jl.printAll(*jsonflag); err != nil {
		return errors.Wrap(err, "failed to print")
	}
	return nil
}

// isSelfSignedRoot checks if a x509 certificate is self signed.
func isSelfSignedRoot(cert *x509.Certificate) bool {
	if cert.AuthorityKeyId != nil {
		return string(cert.AuthorityKeyId) == string(cert.SubjectKeyId) && cert.IsCA
	}
	return cert.Subject.String() == cert.Issuer.String() && cert.IsCA
}

// compareCert compares if two certificates are the same.
func compareCert(cert1, cert2 *x509.Certificate) bool {
	return string(cert2.SubjectKeyId) == string(cert1.SubjectKeyId)
}

// decodePEM returns a slice of pem blocks from byte slice.
func decodePEM(certPEM []byte, filename string) ([]blockInfo, error) {
	var blocklist []blockInfo
	var derror error
	for i := 1; ; i++ {
		data, rest, err := findPEMBlock(certPEM)
		if err != nil {
			derror = errors.Wrapf(err, "failed at file %q at block %q", filename, strconv.Itoa(i))
			if len(blocklist) == 0 {
				block := pem.Block{Bytes: certPEM}
				blocklist = append(blocklist, blockInfo{&block, source{filename, 1}, derror})
				return blocklist, nil
			}
			return nil, derror
		}
		block, _ := pem.Decode(data)
		certPEM = rest
		if block == nil {
			return nil, fmt.Errorf("error while decoding block %d, in file %q", i, filename)
		}
		if strings.Contains(block.Type, "CERTIFICATE") {
			blocklist = append(blocklist, blockInfo{block, source{filename, i}, nil})
		}
		if rest == nil {
			break
		}
	}
	return blocklist, nil
}

// findPEMBlock finds the next PEM Block returns the Block, the rest of the data and returns errors
func findPEMBlock(data []byte) ([]byte, []byte, error) {
	var pemStart = []byte("\n-----BEGIN ")
	var pemEnd = []byte("-----END ")
	var pemEndOfLine = []byte("-----")

	data = bytes.TrimSpace(data)
	rest := data
	if bytes.HasPrefix(data, pemStart[1:]) {
		rest = rest[len(pemStart)-1:]
	} else if i := bytes.Index(data, pemStart); i >= 0 {
		return nil, nil, decodeerror(fmt.Errorf("failed to find PEM block (unexpected symbol(s): \"%q\")", string(data[:i])))
	} else {
		return nil, nil, decodeerror(fmt.Errorf("failed to find PEM block (no \"\\n-----BEGIN TYPE-----\"), in this input: \"%q\"", string(data)))
	}

	typeLine, rest := getLine(rest)
	if !bytes.HasSuffix(typeLine, pemEndOfLine) {
		return nil, nil, decodeerror(fmt.Errorf("failed to find PEM block (no \"----\"- after \"-----BEGIN TYPE\")"))
	}
	typeLine = typeLine[0 : len(typeLine)-len(pemEndOfLine)]
	endIndex := bytes.Index(rest, pemEnd)
	endTrailerIndex := endIndex + len(pemEnd)

	if endIndex < 0 {
		return nil, nil, decodeerror(fmt.Errorf("failed to find PEM block (no \"\\n-----END TYPE-----\")"))
	}

	// After the "-----" of the ending line, there should be the same type
	// and then a final five dashes.
	endTrailer := rest[endTrailerIndex:]
	endTrailerLen := len(typeLine) + len(pemEndOfLine)

	if len(endTrailer) < endTrailerLen {
		return nil, nil, decodeerror(fmt.Errorf("failed to find PEM block (no \"TYPE-----\" after \"-----END \")"))
	}

	restOfEndLine := endTrailer[endTrailerLen:]
	endTrailer = endTrailer[:endTrailerLen]
	if !bytes.HasPrefix(endTrailer, typeLine) ||
		!bytes.HasSuffix(endTrailer, pemEndOfLine) {
		return nil, nil, decodeerror(fmt.Errorf("failed to find PEM block (wrong \"TYPE\" or no \"-----\")"))
	}

	// The line must end with only whitespace.
	s, rest := getLine(restOfEndLine)
	if len(s) != 0 {
		return nil, nil, decodeerror(fmt.Errorf("failed to find PEM block (found non whitespace)"))
	}
	end := endIndex + 2*len(typeLine) + 2*len(pemEndOfLine) + len(pemStart) + len(pemEnd) + 2
	if end >= len(data) {
		end = len(data)
	}
	data = data[:end]
	if data[len(data)-1] == '\r' {
		data = data[:len(data)-1]
	}

	validate := data[len(pemStart)+len(pemEndOfLine)+len(typeLine) : len(data)]
	if i := bytes.Index(validate, pemStart[1:]); i >= 0 {
		return nil, nil, decodeerror(fmt.Errorf("failed to find PEM block (two \"-----BEGIN TYPE-----\" found"))
	}
	return bytes.TrimSpace(data), bytes.TrimSpace(rest), nil
}

// getLine results the first \r\n or \n delineated line from the given byte
// array. The line does not include trailing whitespace or the trailing new
// line bytes. The remainder of the byte array (also not including the new line
// bytes) is also returned and this will always be smaller than the original
// argument.
//
// vgl from encoding/pem
func getLine(data []byte) (line, rest []byte) {
	i := bytes.IndexByte(data, '\n')
	var j int
	if i < 0 {
		i = len(data)
		j = i
	} else {
		j = i + 1
		if i > 0 && data[i-1] == '\r' {
			i--
		}
	}
	return bytes.TrimRight(data[0:i], " \t"), data[j:]
}

// parse iterates through all pem blocks and parses it into x509 certificate.
func (el *entryList) parse(blocklist []blockInfo) error {
nextBlock:
	for _, bi := range blocklist {
		c, err := x509.ParseCertificate(bi.block.Bytes)
		if err != nil {
			if bi.err != nil {
				return bi.err
			}
			return errors.Wrapf(err, "failed to parse block %q, in file %q", strconv.Itoa(bi.src.Position), bi.src.Name)
		}

		for idx, ent := range *el {
			if compareCert(c, ent.cert) {
				(*el)[idx].source = append((*el)[idx].source, bi.src)
				continue nextBlock
			}
		}
		e := entry{
			cert:   c,
			source: []source{bi.src},
		}
		*el = append(*el, e)
	}
	return nil
}

// verifyAllCerts verifies all certificates from the entry list
// and only uses the system root certificates
// if the flag disablesysroot is not set.
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

// verify returns a x509 certificate chain slice when the certificate was able to be verified,
// otherwise an error is returned.
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

// mergeChain merges all chain slices from the entryList together into a single chain slice.
func (el entryList) mergeChain() [][]*x509.Certificate {
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
	return reducedchain
}

// isSubchain checks if subchain is a branch of the mainchain.
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

// initJSONList initializes a jsonList from a list of x509 certificate chains.
func (el entryList) initJSONList(chainlist [][]*x509.Certificate) jsonList {
	var jl jsonList
	for _, chainval := range chainlist {
		for certidx, certval := range chainval {
			certentry := el.getEntryfromChain(certval)
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
	return jl
}

// getEntryfromChain returns a entry object from a x509 certifcate.
// If the certificate could be found in the entryList,
// source and source-position are added.
func (el entryList) getEntryfromChain(certval *x509.Certificate) entry {
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
	return certentry
}

// initJSON initializes a jsonEntry object from an entry.
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

// initNames initializes a jsonName object from a pkix.Name object.
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

// initKeyUsage initializes a string slice with filled the Key Usages from a x509 certificate.
func initKeyUsage(val x509.KeyUsage) []string {
	var keyusage []string
	if val&x509.KeyUsageDigitalSignature > 0 {
		keyusage = append(keyusage, "Digital Signature")
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
		keyusage = append(keyusage, "Encipher Only")
	}
	if val&x509.KeyUsageDecipherOnly > 0 {
		keyusage = append(keyusage, "Decipher Only")
	}
	return keyusage
}

// initExtKeyUsage initializes a string slice with filled the extended Key Usages from a x509 certificate.
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

// initAltNames initializes a string slice filled with the alternative names from a x509 certificate.
func initAltNames(cert *x509.Certificate) jsonAltname {
	var altnames jsonAltname
	for _, v := range cert.DNSNames {
		altnames.DNS = append(altnames.DNS, v)
	}
	for _, v := range cert.EmailAddresses {
		altnames.EMAIL = append(altnames.EMAIL, v)
	}
	for _, v := range cert.IPAddresses {
		altnames.IP = append(altnames.IP, v.String())
	}
	for _, v := range cert.URIs {
		altnames.URL = append(altnames.URL, v.RawQuery)
	}
	return altnames
}

// initVerified initializes a verifiedInfo object from an entry.
func initVerified(e entry) verifiedInfo {
	if e.verified == nil {
		if isSelfSignedRoot(e.cert) {
			return verifiedInfo{true, "self signed"}
		}
		return verifiedInfo{true, ""}
	}
	return verifiedInfo{false, e.verified.Error()}
}

// printAll calls printJSON or printINFO depending if the jsonflag is set or not.
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

// printJSON pritns all elements from jsonlist in JSON syntax.
func (jl jsonList) printJSON() error {
	data, err := json.MarshalIndent(jl, "", "  ")
	if err != nil {
		return errors.Wrap(err, "failed to convert to json")
	}
	fmt.Println(string(data))
	return nil
}

// printInfo prints all elements from the jsonList.
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

// printEntry prints a jsonEntry object.
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
	fmt.Println(tab, "Alt Names        :", formatAltnames(jsn.AltNames))
	fmt.Println(tab, "Subject Key ID   :", jsn.SubjectKeyID)
	fmt.Println(tab, "Authority Key ID :", jsn.AuthorityKeyID)
	fmt.Println(tab, "CA               :", jsn.CA)
	fmt.Println(tab, "Verified         :", formatVerified(jsn.Verified))
	printSources(jsn.Source, tab)
	fmt.Println()
	return
}

// formatVerified formats a verifiedInfo object to a string.
func formatVerified(vi verifiedInfo) string {
	if vi.Info != "" {
		return fmt.Sprintf("%v (%s)", vi.Status, vi.Info)
	}
	return fmt.Sprintf("%v", vi.Status)
}

// formatName formats a jsonName object to a string.
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

// formatAltnames formats a jsonAltname object to a string
func formatAltnames(val jsonAltname) string {
	var altnames, names []string

	for _, v := range val.DNS {
		names = append(names, "DNS:"+v)
	}
	if dns := strings.Join(names, ", "); dns != "" {
		altnames = append(altnames, dns)
	}

	names = nil
	for _, v := range val.EMAIL {
		names = append(names, "EMAIl:"+v)
	}
	if email := strings.Join(names, ", "); email != "" {
		altnames = append(altnames, email)
	}

	names = nil
	for _, v := range val.IP {
		names = append(names, "IP:"+v)
	}
	if ip := strings.Join(names, ", "); ip != "" {
		altnames = append(altnames, ip)
	}

	names = nil
	for _, v := range val.URL {
		names = append(names, "URL:"+v)
	}
	if url := strings.Join(names, ", "); url != "" {
		altnames = append(altnames, url)
	}
	return strings.Join(altnames, ", ")
}

// printSources prints the source list.
// tab is concatinated in front of the message in every printed line.
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
			sourcetext += " | Block: " + strconv.Itoa(src.Position)
		}
		fmt.Println(tab, "Source           :", sourcetext)
	}
}

// encodeHex return a more readable out put of hex values.
func encodeHex(val []byte) string {
	var names []string
	for _, v := range val {
		names = append(names, hex.EncodeToString([]byte{v}))
	}
	return strings.Join(names, ":")
}
