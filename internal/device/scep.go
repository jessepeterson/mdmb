package device

import (
	"context"
	"crypto"
	_ "crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/jessepeterson/cfgprofiles"
	mdmbscepclient "github.com/jessepeterson/mdmb/scepclient"
	"github.com/smallstep/scep"
	"github.com/smallstep/scep/x509util"
)

const defaultRSAKeySize = 1024

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

// borrowed from x509.go
func newKeyUsageExtension(keyUsage int) (e pkix.Extension, err error) {
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

func keyFromSCEPProfilePayload(pl *cfgprofiles.SCEPPayload, rand io.Reader) (*rsa.PrivateKey, error) {
	plc := pl.PayloadContent
	if plc.KeyType != "" && plc.KeyType != "RSA" {
		return nil, errors.New("only RSA keys supported")
	}
	keySize := defaultRSAKeySize
	if plc.KeySize > 0 {
		keySize = plc.KeySize
	}
	return rsa.GenerateKey(rand, keySize)
}

func replaceSCEPVars(device *Device, istrs []string) (ostrs []string) {
	// % /usr/libexec/mdmclient dumpSCEPVars
	r := strings.NewReplacer([]string{
		"%ComputerName%", device.ComputerName,
		"%HardwareUUID%", device.UDID,
		"%SerialNumber%", device.Serial,
		// "%HostName%", "TODO_HostName",
		// "%LocalHostName%", "TODO_LocalHostName",
		// "%MACAddress%", "TODO_MACAddress",
	}...)
	for _, istr := range istrs {
		ostrs = append(ostrs, r.Replace(istr))
	}
	return
}

func csrFromSCEPProfilePayload(pl *cfgprofiles.SCEPPayload, device *Device, rand io.Reader, privKey *rsa.PrivateKey) ([]byte, error) {
	plc := pl.PayloadContent

	tmpl := &x509util.CertificateRequest{
		ChallengePassword: plc.Challenge,
	}
	// macOS seems to default using just Digital Signature
	keyUsage := int(x509.KeyUsageDigitalSignature)
	if plc.KeyUsage != 0 {
		keyUsage = plc.KeyUsage
	}
	// this is a bitfield that appears to match Go/X509 definition
	keyUsageExtn, err := newKeyUsageExtension(keyUsage)
	if err != nil {
		return nil, err
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, keyUsageExtn)
	for _, onvg := range plc.Subject {
		for _, onv := range onvg {
			if len(onv) < 2 {
				return nil, fmt.Errorf("invalid OID in SCEP payload: %v", onv)
			}
			values := replaceSCEPVars(device, onv[1:])
			switch onv[0] {
			case "C":
				tmpl.Subject.Country = values
			case "L":
				tmpl.Subject.Locality = values
			case "ST":
				// TODO: Are these interchangeable?
				tmpl.Subject.Province = values
			case "O":
				tmpl.Subject.Organization = values
			case "OU":
				tmpl.Subject.OrganizationalUnit = values
			case "CN":
				tmpl.Subject.CommonName = values[0]
			default:
				// TODO: arbitrary OIDs not yet supported
				return nil, fmt.Errorf("unhandled OID in SCEP payload: %v", onv)
			}
		}
	}
	// macOS seems to fill a default CN of the PayloadIdentifier if not present
	if tmpl.Subject.CommonName == "" {
		tmpl.Subject.CommonName = pl.PayloadIdentifier
	}
	// TODO: SANs
	return x509util.CreateCertificateRequest(rand, tmpl, privKey)
}

func selfSign() (*rsa.PrivateKey, *x509.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	timeNow := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "SCEP SIGNER",
		},
		NotBefore: timeNow,
		NotAfter:  timeNow.Add(time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	return priv, cert, err
}

func scepCertsSelector(fingerprint []byte) (scep.CertsSelector, error) {
	if len(fingerprint) < 1 {
		return scep.NopCertsSelector(), nil
	}
	hashType := crypto.Hash(0)
	switch len(fingerprint) {
	case 16:
		hashType = crypto.MD5
	case 20:
		hashType = crypto.SHA1
	case 32:
		hashType = crypto.SHA256
	default:
		return nil, fmt.Errorf("unsupported scep fingerprint length: %d", len(fingerprint))
	}
	return scep.FingerprintCertsSelector(hashType, fingerprint), nil
}

func scepNewPKCSReq(ctx context.Context, csrBytes []byte, url, _, caMessage string, fingerprint []byte) (*x509.Certificate, error) {
	selector, err := scepCertsSelector(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("scep cert selector: %w", err)
	}

	c, err := mdmbscepclient.New(url, mdmbscepclient.WithSignerKeypair(func(context.Context) (*x509.Certificate, *rsa.PrivateKey, error) {
		key, cert, err := selfSign()
		return cert, key, err
	}))
	if err != nil {
		return nil, fmt.Errorf("creating scep client: %w", err)
	}

	// re-parse the x509util CertificateRequest (which now contains any challenge password)
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing csr: %w", err)
	}

	cert, err := c.FullSign(ctx, csr, []byte(caMessage), selector)
	if err != nil {
		return nil, fmt.Errorf("scep: %w", err)
	}

	return cert, nil
}
