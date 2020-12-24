package main

import (
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jessepeterson/cfgprofiles"
	"github.com/micromdm/scep/crypto/x509util"
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

func keyFromSCEPProfilePayload(rand io.Reader, pl *cfgprofiles.SCEPPayload) (*rsa.PrivateKey, error) {
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

func replaceSCEPVars(device interface{}, istrs []string) (ostrs []string) {
	// % /usr/libexec/mdmclient dumpSCEPVars
	r := strings.NewReplacer([]string{
		"%ComputerName%", "TODO_ComputerName",
		"%HardwareUUID%", "TODO_HardwareUUID",
		// "%HostName%", "TODO_HostName",
		// "%LocalHostName%", "TODO_LocalHostName",
		// "%MACAddress%", "TODO_MACAddress",
		"%SerialNumber%", "TODO_SerialNumber",
	}...)
	for _, istr := range istrs {
		ostrs = append(ostrs, r.Replace(istr))
	}
	return
}

func csrFromSCEPProfilePayload(rand io.Reader, pl *cfgprofiles.SCEPPayload, priv *rsa.PrivateKey) ([]byte, error) {
	plc := pl.PayloadContent

	tmpl := &x509util.CertificateRequest{
		ChallengePassword: plc.Challenge,
	}
	if plc.KeyUsage != 0 {
		// this is a bitfield that appears to match Go/X509 definition
		keyUsageExtn, err := newKeyUsageExtension(plc.KeyUsage)
		if err != nil {
			return nil, err
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, keyUsageExtn)
	}
	for _, onvg := range plc.Subject {
		for _, onv := range onvg {
			if len(onv) < 2 {
				return nil, fmt.Errorf("invalid OID in SCEP payload: %v", onv)
			}
			// TODO: replace device %variable% names
			values := replaceSCEPVars(nil, onv[1:])
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
	// TODO: SANs
	return x509util.CreateCertificateRequest(rand, tmpl, priv)
}
