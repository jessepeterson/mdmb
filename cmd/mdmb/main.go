package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	stdlog "log"
	"os"

	"github.com/go-kit/kit/log"
	"github.com/groob/plist"
	"github.com/jessepeterson/cfgprofiles"
	scepclient "github.com/micromdm/scep/client"
	"github.com/micromdm/scep/crypto/x509util"
)

func main() {
	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	// var (
	// 	dbPath = f.String("db", "mdmb.db", "mdmb database file path")
	// )
	f.Usage = func() {
		fmt.Fprintf(f.Output(), "%s [flags] <subcommand> [flags]\n", f.Name())
		fmt.Fprint(f.Output(), "\nFlags:\n")
		f.PrintDefaults()
		fmt.Fprint(f.Output(), "\nSubcommands:\n")
		fmt.Fprintln(f.Output(), "    enroll\tenroll devices into MDM")
	}
	f.Parse(os.Args[1:])

	if len(f.Args()) < 1 {
		fmt.Fprintln(f.Output(), "no subcommand supplied")
		f.Usage()
		os.Exit(2)
	}

	switch f.Args()[0] {
	case "enroll":
		enroll(f.Args()[1:], f.Usage)
	case "help":
		f.Usage()
	default:
		fmt.Fprintf(f.Output(), "invalid subcommand: %s\n", f.Args()[0])
		f.Usage()
		os.Exit(2)
	}
}

func enroll(args []string, usage func()) {
	f := flag.NewFlagSet("enroll", flag.ExitOnError)
	var (
		// enrollType = f.String("type", "profile", "enrollment type")
		// number     = f.Int("n", 1, "number of devices")
		url  = f.String("url", "", "URL pointing to enrollment spec (e.g. profile)")
		file = f.String("file", "", "file of enrollment spec (e.g. profile)")
	)
	f.Usage = func() {
		usage()
		fmt.Fprintf(f.Output(), "\nFlags for %s subcommand:\n", f.Name())
		f.PrintDefaults()
	}
	f.Parse(args)

	if (*url == "" && *file == "") || (*url != "" && *file != "") {
		fmt.Fprintln(f.Output(), "must specify one enrollment url or file")
		f.Usage()
		os.Exit(2)
	}

	if *url != "" {
		fmt.Fprintln(f.Output(), "-url not yet supported")
		os.Exit(1)
	}

	if err := enrollWithFile(*file); err != nil {
		stdlog.Fatal(err)
	}

	// c := client.NewMDMClient()
	// fmt.Println(c.UDID)
}

func enrollWithFile(path string) error {

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	profile := &cfgprofiles.Profile{}

	dec := plist.NewDecoder(f)
	if err := dec.Decode(profile); err != nil {
		return err
	}

	mdmPlds := profile.MDMPayloads()
	if len(mdmPlds) != 1 {
		return errors.New("invalid number of MDM payloads")
	}
	mdmPld := mdmPlds[0]

	fmt.Printf("CheckIn:\t%s\nConnect:\t%s\n", mdmPld.CheckInURL, mdmPld.ServerURL)

	scepPlds := profile.SCEPPayloads()
	if len(mdmPlds) != 1 {
		return errors.New("invalid number of MDM payloads")
	}
	scepPld := scepPlds[0]

	scepURL := scepPld.PayloadContent.URL
	fmt.Printf("SCEP URL:\t%s\n", scepURL)

	logger := log.NewLogfmtLogger(os.Stderr)
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	cl, err := scepclient.New(scepURL, logger)
	if err != nil {
		return err
	}
	// fmt.Println(cl.Supports("POSTPKIOperation"))
	fmt.Println(cl)

	devKey, err := KeyFromSCEPProfilePayload(rand.Reader, scepPld)
	if err != nil {
		return err
	}

	csrBytes, err := CSRFromSCEPProfilePayload(rand.Reader, scepPld, devKey)
	if err != nil {
		return err
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}

	f, err = os.Create("/tmp/csr.pem")
	if err != nil {
		return nil
	}
	defer f.Close()
	err = pem.Encode(f, pemBlock)
	if err != nil {
		return err
	}

	return nil
}

// KeyFromSCEPProfilePayload creates a private key from a SCEP configuration profile payload
func KeyFromSCEPProfilePayload(rand io.Reader, pl *cfgprofiles.SCEPPayload) (interface{}, error) {
	plc := pl.PayloadContent
	if plc.KeyType != "RSA" && plc.KeyType != "" {
		return nil, errors.New("only RSA keys supported")
	}
	keySize := 1024
	if plc.KeySize > 0 {
		keySize = plc.KeySize
	}
	return rsa.GenerateKey(rand, keySize)
}

// borrowed from x509.go
func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

// borrowed from x509.go
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}

// (largely) borrowed from x509.go
func NewKeyUsageExtension(keyUsage int) (e pkix.Extension, err error) {
	e.Id = asn1.ObjectIdentifier{2, 5, 29, 15}
	e.Critical = true

	var a [2]byte
	a[0] = reverseBitsInAByte(byte(keyUsage))
	a[1] = reverseBitsInAByte(byte(keyUsage >> 8))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := a[:l]
	e.Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
	return e, err
}

// CSRFromSCEPProfilePayload creates a certificate request from a SCEP configuration profile payload
func CSRFromSCEPProfilePayload(rand io.Reader, pl *cfgprofiles.SCEPPayload, priv interface{}) ([]byte, error) {
	plc := pl.PayloadContent

	tmpl := &x509util.CertificateRequest{
		ChallengePassword: plc.Challenge,
	}
	if plc.KeyUsage != 0 {
		keyUsageExtn, err := NewKeyUsageExtension(plc.KeyUsage)
		if err != nil {
			return nil, err
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, keyUsageExtn)
	}
	// TODO: Subject
	// TODO: SANs
	return x509util.CreateCertificateRequest(rand, tmpl, priv)
}
