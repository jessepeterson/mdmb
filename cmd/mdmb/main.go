package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"os"

	"github.com/groob/plist"
	"github.com/jessepeterson/cfgprofiles"
	"github.com/jessepeterson/mdmb/internal/device"
	"go.mozilla.org/pkcs7"
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

	dev := &device.Device{
		UDID:         "475F0A29-6FCE-419E-A30F-9FF616FD2B87",
		Serial:       "P3IJDS49Z90A",
		ComputerName: "Malik's computer",
	}

	dev.IdentityPrivateKey, err = keyFromSCEPProfilePayload(scepPld, rand.Reader)
	if err != nil {
		return err
	}

	csrBytes, err := csrFromSCEPProfilePayload(scepPld, dev, rand.Reader)
	if err != nil {
		return err
	}

	err = writeCSR(csrBytes, "/tmp/csr.pem")
	if err != nil {
		return err
	}
	fmt.Println("wrote CSR to /tmp/csr.pem")

	dev.IdentityCertificate, err = scepNewPKCSReq(csrBytes, scepURL, scepPld.PayloadContent.Challenge)
	if err != nil {
		return err
	}

	if err := writeCert(dev.IdentityCertificate, "/tmp/cert.pem"); err != nil {
		return err
	}
	fmt.Println("wrote cert to /tmp/cert.pem")

	if !mdmPld.SignMessage {
		return errors.New("non-SignMessage (mTLS) enrollment not supported")
	}

	fmt.Println("sending Authenticate")
	err = Authenticate(dev, mdmPld.Topic, mdmPld.CheckInURL)
	if err != nil {
		return err
	}

	fmt.Println("sending TokenUpdate")
	err = TokenUpdate(dev, mdmPld.Topic, mdmPld.CheckInURL)
	if err != nil {
		return err
	}

	return nil
}

func Authenticate(device *device.Device, topic, url string) error {
	ar := &AuthenticationRequest{
		DeviceName:  device.ComputerName,
		MessageType: "Authenticate",
		Topic:       topic,
		UDID:        device.UDID,

		// non-required
		SerialNumber: device.Serial,
	}

	err := CheckinRequest(ar, device, url)
	if err != nil {
		return err
	}

	return nil
}

// AuthenticationRequest ...
type AuthenticationRequest struct {
	BuildVersion string `plist:",omitempty"`
	DeviceName   string
	IMEI         string `plist:",omitempty"`
	MEID         string `plist:",omitempty"`
	MessageType  string
	Model        string `plist:",omitempty"`
	ModelName    string `plist:",omitempty"`
	OSVersion    string `plist:",omitempty"`
	ProductName  string `plist:",omitempty"`
	SerialNumber string `plist:",omitempty"`
	Topic        string
	UDID         string
	EnrollmentID string `plist:",omitempty"` // macOS 10.15 and iOS 13.0 and later
}

func mdmP7Sign(body []byte, cert *x509.Certificate, priv *rsa.PrivateKey) (string, error) {
	signedData, err := pkcs7.NewSignedData(body)
	if err != nil {
		return "", err
	}
	signedData.AddSigner(cert, priv, pkcs7.SignerInfoConfig{})
	signedData.Detach()
	sig, err := signedData.Finish()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

type TokenUpdateRequest struct {
	AwaitingConfiguration bool   `plist:",omitempty"`
	EnrollmentID          string `plist:",omitempty"` // macOS 10.15 and iOS 13.0 and later
	EnrollmentUserID      string `plist:",omitempty"` // macOS 10.15 and iOS 13.0 and later
	MessageType           string
	NotOnConsole          bool `plist:",omitempty"`
	PushMagic             string
	Token                 []byte
	Topic                 string
	UDID                  string
	UnlockToken           []byte `plist:",omitempty"`
	UserShortName         string `plist:",omitempty"`
	UserID                string `plist:",omitempty"`
	UserLongName          string `plist:",omitempty"`
}

func CheckinRequest(i interface{}, device *device.Device, url string) error {
	plistBytes, err := plist.Marshal(i)
	if err != nil {
		return err
	}

	mdmSig, err := mdmP7Sign(plistBytes, device.IdentityCertificate, device.IdentityPrivateKey)
	if err != nil {
		return err
	}

	client := &http.Client{}
	req, err := http.NewRequest("PUT", url, bytes.NewReader(plistBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Mdm-Signature", mdmSig)

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("Checkin Request failed with HTTP status: %d", res.StatusCode)
	}

	return nil
}

func TokenUpdate(device *device.Device, topic, url string) error {
	tu := &TokenUpdateRequest{
		MessageType: "TokenUpdate",
		PushMagic:   "PushMagic",
		Token:       []byte("token"),
		Topic:       topic,
		UDID:        device.UDID,
	}

	err := CheckinRequest(tu, device, url)
	if err != nil {
		return err
	}

	return nil
}

func writeCSR(csr []byte, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}
	err = pem.Encode(f, pemBlock)
	if err != nil {
		return err
	}
	return nil
}

func writeCert(c *x509.Certificate, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	}
	err = pem.Encode(f, pemBlock)
	if err != nil {
		return err
	}
	return nil
}
