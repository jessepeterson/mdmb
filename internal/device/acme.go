package device

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/jessepeterson/cfgprofiles"
	"github.com/jessepeterson/mdmb/internal/attest"
	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"github.com/smallstep/certinfo"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
)

func keyFromACMECertificateProfilePayload(plc *cfgprofiles.ACMECertificatePayload, rand io.Reader) (crypto.Signer, error) {
	// TODO: additional validation based on values for HardwareBound; KeyIsExtractable
	switch plc.KeyType {
	case "RSA": // 1024 - 4096 bits are valid
		keySize := 2048
		if plc.KeySize > 0 {
			keySize = plc.KeySize
		}
		return rsa.GenerateKey(rand, keySize)
	case "ECSECPrimeRandom": // 192, 256, 384 or 521
		var c elliptic.Curve
		switch plc.KeySize {
		case 192:
			return nil, errors.New("P-192 is not supported") // not supported in Go
		case 256:
			c = elliptic.P256()
		case 384:
			c = elliptic.P384()
		case 521:
			c = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve: %d", plc.KeySize)
		}
		return ecdsa.GenerateKey(c, rand)
	case "":
		return nil, errors.New("KeyType is required in ACMECertificate payload")
	default:
		return nil, fmt.Errorf("KeyType %q is not supported in ACMECertificate payload", plc.KeyType)
	}
}

func newACMECertificateRequest(ctx context.Context, device *Device, pl *cfgprofiles.ACMECertificatePayload) (crypto.PrivateKey, *x509.Certificate, error) {
	mustAttest := pl.Attest
	if !mustAttest {
		// The ACME client currently requires a solver that performs attestation
		// using a fake attestation CA. There's currently no other way to prove
		// ownership over an ACME identifier, so we can only return an error when
		// Attest is set to false. This also means that a macOS device can't currently
		// be simulated, because for macOS, Attest must be set to false.
		return nil, nil, errors.New("non-attested ACMECertificate payload are currently not supported")
	}

	isHardwareBound := pl.HardwareBound
	if mustAttest && !isHardwareBound {
		return nil, nil, errors.New(`if key "Attest" is true, "HardwareBound" must be true`)
	}

	clientIdentifier := pl.ClientIdentifier
	if clientIdentifier == "" {
		return nil, nil, errors.New(`"ClientIdentifier" required`)
	}

	directoryURL := pl.DirectoryURL
	if directoryURL == "" {
		return nil, nil, errors.New(`"DirectoryURL" required`)
	}
	if _, err := url.Parse(directoryURL); err != nil {
		return nil, nil, fmt.Errorf(`failed parsing DirectoryURL: %w`, err)
	}

	if pl.SubjectAltName != nil {
		// currently a flow in which SubjectAltName is set is not supported,
		// because the ACME client that's currently in use will automatically
		// set the challenge types based on contents of the CSR.
		// TODO: determine how we can use/instruct the `acmez` client to
		// only use specific challenge types. In this case `device-attest-01`.
		return nil, nil, errors.New(`"SubjectAltName" not yet supported`)
	}

	signer, err := keyFromACMECertificateProfilePayload(pl, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating key for ACMECertificate payload: %w", err)
	}

	attestationCA, ok := attest.FromContext(ctx)
	if !ok {
		return nil, nil, errors.New("ACMECertificate payload processing requires a (fake) Attestation CA to be configured")
	}

	deviceAttestSolver := &attSolver{
		attestationCA: attestationCA,
		signer:        signer,
		device:        device,
	}

	client := acmez.Client{
		Client: &acme.Client{
			Directory: directoryURL,
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true, // just tinkering locally
					},
				},
			},
		},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeDeviceAttest01: deviceAttestSolver,
		},
	}

	// Before a certificate can be obtained, an ACME account needs to be
	// created. This requires a private key.
	accountPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed generating account key: %w", err)
	}
	account := acme.Account{
		Contact:              []string{"mailto:someone@example.com"},
		TermsOfServiceAgreed: true,
		PrivateKey:           accountPrivateKey,
	}

	// Create a new ACME account. It is currently not being persisted,
	// so a new one is created every time a certificate is requested.
	account, err = client.NewAccount(ctx, account)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating new account: %w", err)
	}

	// Create a CSR for the ACME flow to use.
	csr, err := createACMECSR(device, pl, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating CSR: %w", err)
	}

	// Once the client, account, private key and CSR are all ready,
	// start the request for a new certificate.
	acmeCertificateChains, err := client.ObtainCertificateUsingCSR(ctx, account, csr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed obtaining certificate: %w", err)
	}
	if len(acmeCertificateChains) == 0 {
		return nil, nil, errors.New("no certificates obtained")
	}

	// ACME servers should usually give you the entire certificate chain
	// in PEM format. The response can contain multiple chains.
	acmeCertificateChain := acmeCertificateChains[0]
	log.Printf("[DEBUG] Certificate %q:\n%s\n\n", acmeCertificateChain.URL, acmeCertificateChain.ChainPEM)
	chain, err := pemutil.ParseCertificateBundle(acmeCertificateChain.ChainPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parsing certificate bundle: %w", err)
	}
	for _, c := range chain {
		s, err := certinfo.CertificateText(c)
		if err != nil {
			return nil, nil, fmt.Errorf("failed getting certificate text: %w", err)
		}
		fmt.Println(s)
	}

	// first cert in the chain is the new leaf
	certificate := chain[0]

	return signer, certificate, nil
}

func createACMECSR(device *Device, pl *cfgprofiles.ACMECertificatePayload, key crypto.Signer) (*x509.CertificateRequest, error) {
	clientIdentifier := pl.ClientIdentifier
	template := &x509.CertificateRequest{
		PublicKey: key.Public(),
	}

	// keyUsage defaults to Digital Signature
	keyUsage := int(x509.KeyUsageDigitalSignature)
	if pl.UsageFlags != 0 {
		keyUsage = pl.UsageFlags
	}

	// this is a bitfield that appears to match Go/X509 definition
	keyUsageExtn, err := newKeyUsageExtension(keyUsage)
	if err != nil {
		return nil, fmt.Errorf("failed creating new KeyUsage extension: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, keyUsageExtn)

	// add the ExtKeyUsage extension. CAs may not always respect this value.
	extKeyUsageExtn, err := newExtendedKeyUsageExtension(pl.ExtendedKeyUsage)
	if err != nil {
		return nil, fmt.Errorf("failed creating ExtKeyUsage extension: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, extKeyUsageExtn)

	// process the requested ACMECertificate Subject contents
	for _, onvg := range pl.Subject {
		for _, onv := range onvg {
			if len(onv) < 2 {
				return nil, fmt.Errorf("invalid OID in ACME payload: %v", onv)
			}
			values := replaceSCEPVars(device, onv[1:]) // TODO: check if this is done for ACME too
			switch onv[0] {
			case "C":
				template.Subject.Country = values
			case "L":
				template.Subject.Locality = values
			case "ST":
				// TODO: Are these interchangeable?
				template.Subject.Province = values
			case "O":
				template.Subject.Organization = values
			case "OU":
				template.Subject.OrganizationalUnit = values
			case "CN":
				template.Subject.CommonName = values[0]
			default:
				// TODO: arbitrary OIDs not yet supported
				return nil, fmt.Errorf("unhandled OID in ACME payload: %v", onv)
			}
		}
	}

	// prepare the SANs for the CSR. Currently only one PermanentIdentifier
	// is supported. The PermanentIdentifier is required to contain the value
	// of the ClientIdentifier in `step-ca`.
	// TODO: determine / verify if we want to include the PermanentIdentifier
	// in the CSR or not. The Apple ACME client may not be including it, so
	// then I think we should remove it here too. But the ACME client does
	// extract the type of ACME identifier to request for from the CSR, so it
	// needs to be in there, unless we change the ACME client implementation
	// to take the identifiers in a different way.
	san := pl.SubjectAltName
	otherSANs := []x509util.SubjectAlternativeName{}
	var dnsNames, emailAddresses []string
	var uris []*url.URL
	if san != nil {
		dnsNames = x509util.MultiString(san.DNSNames)
		emailAddresses = x509util.MultiString(san.RFC822Names)
		for _, uri := range san.URIs {
			u, err := url.Parse(uri)
			if err != nil {
				return nil, fmt.Errorf("failed parsing %q as URL: %w", uri, err)
			}
			uris = append(uris, u)
		}
		for _, pn := range san.NTPrincipals {
			otherSANs = append(otherSANs, x509util.SubjectAlternativeName{
				Type:  "1.3.6.1.4.1.311.20.2.3",   // User Principal Name / NTPrincipalName
				Value: fmt.Sprintf("utf8:%s", pn), // e.g. utf8:test@example.com
			})
		}
	}
	permanentIdentifiers := []string{clientIdentifier}
	for _, pi := range permanentIdentifiers {
		otherSANs = append(otherSANs, x509util.SubjectAlternativeName{
			Type:  x509util.PermanentIdentifierType,
			Value: pi,
		})
	}
	subjectIsEmpty := template.Subject.CommonName == ""
	ext, err := createSubjectAltNameExtension(dnsNames, emailAddresses, nil, uris, otherSANs, subjectIsEmpty)
	if err != nil {
		return nil, fmt.Errorf("failed creating SubjectAltName extension")
	}
	template.ExtraExtensions = append(template.ExtraExtensions,
		pkix.Extension{
			Id:       asn1.ObjectIdentifier(ext.ID),
			Critical: ext.Critical,
			Value:    ext.Value,
		},
	)

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("failed creating certificate request: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("failed parsing certificate request: %w", err)
	}

	return csr, nil
}

func newExtendedKeyUsageExtension(extKeyUsageOIDs []string) (e pkix.Extension, err error) {
	e.Id = asn1.ObjectIdentifier{2, 5, 29, 37}
	oids := make([]asn1.ObjectIdentifier, len(extKeyUsageOIDs))
	for i, u := range extKeyUsageOIDs {
		parts := strings.Split(u, ".")
		oid := []int{}
		for _, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil {
				return e, fmt.Errorf("failed parsing %q as OID: %w", u, err)
			}
			oid = append(oid, n)
		}
		oids[i] = oid // NOTE: this does not validate if the extKeyUsage OID is a known/registered one
	}
	e.Value, err = asn1.Marshal(oids)
	return
}

// attSolver is a acmez.Solver that mimics the Apple attestation flow, backed
// by a fake Attestation CA under the users control.
type attSolver struct {
	attestationCA *attest.CA
	signer        crypto.Signer
	device        *Device
}

func (s *attSolver) Present(ctx context.Context, chal acme.Challenge) error {
	log.Printf("[DEBUG] present: %#v", chal)
	return nil
}

func (s *attSolver) CleanUp(ctx context.Context, chal acme.Challenge) error {
	log.Printf("[DEBUG] cleanup: %#v", chal)
	return nil
}

type attestationObject struct {
	Format       string                 `json:"fmt"`
	AttStatement map[string]interface{} `json:"attStmt,omitempty"`
}

var (
	oidAppleSerialNumber                    = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 1}
	oidAppleUniqueDeviceIdentifier          = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 2}
	oidAppleSecureEnclaveProcessorOSVersion = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 10, 2}
	oidAppleNonce                           = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 11, 1}
)

func (s *attSolver) Payload(ctx context.Context, chal acme.Challenge) (interface{}, error) {
	log.Printf("[DEBUG] payload: %#v", chal)

	// TODO: different behavior between user and device enrollments: when
	// a device enrolls, the UDID and serial are included in the attestation
	// certificate. For user enrolments, this is not the case for privacy
	// reasons.

	nonceSum := sha256.Sum256([]byte(chal.Token)) // the nonce is just the SHA256 of the challenge token
	template := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "fake attestation cert"},
		PublicKey: s.signer.Public(), // attestation leaf must have same public key fingerprint as the ACME certificate CSR
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidAppleSerialNumber,
				Value:    []byte(s.device.Serial),
				Critical: false,
			},
			{
				Id:       oidAppleUniqueDeviceIdentifier,
				Value:    []byte(s.device.UDID),
				Critical: false,
			},
			{
				Id:       oidAppleSecureEnclaveProcessorOSVersion,
				Value:    []byte("16.0"), // TODO: make dynamic, based on type of device?
				Critical: false,
			},
			{
				Id:       oidAppleNonce,
				Value:    nonceSum[:],
				Critical: false,
			},
		},
	}

	// TODO: Apple devices will cache the attestation cert until
	// a fresh attestation is requested via the MDM solution. This
	// simulator currently doesn't do that and will always create
	// a new attestation certificate.
	chain, err := s.attestationCA.Sign(template)
	if err != nil {
		return nil, err
	}
	chainBytes := make([][]byte, len(chain))
	for i, cert := range chain {
		chainBytes[i] = cert.Raw
	}

	attObj := &attestationObject{
		Format: "apple",
		AttStatement: map[string]interface{}{
			"x5c": chainBytes,
		},
	}
	b, err := cbor.Marshal(attObj)
	if err != nil {
		return nil, err
	}

	attObjString := base64.RawURLEncoding.EncodeToString(b)

	return map[string]string{
		"attObj": attObjString,
	}, nil
}

var (
	oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// createSubjectAltNameExtension will construct an Extension containing all
// SubjectAlternativeNames held in a Certificate. It implements more types than
// the golang x509 library, so it is used whenever OtherName or RegisteredID
// type SANs are present in the certificate.
//
// See also https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.1.6
//
// TODO(hs): this was copied from go.step.sm/crypto/x509util to make it easier
// to create the SAN extension for testing purposes. Should it be exposed instead?
func createSubjectAltNameExtension(dnsNames, emailAddresses x509util.MultiString, ipAddresses x509util.MultiIP, uris x509util.MultiURL, sans []x509util.SubjectAlternativeName, subjectIsEmpty bool) (x509util.Extension, error) {
	var zero x509util.Extension

	var rawValues []asn1.RawValue
	for _, dnsName := range dnsNames {
		rawValue, err := x509util.SubjectAlternativeName{
			Type: x509util.DNSType, Value: dnsName,
		}.RawValue()
		if err != nil {
			return zero, err
		}
		rawValues = append(rawValues, rawValue)
	}

	for _, emailAddress := range emailAddresses {
		rawValue, err := x509util.SubjectAlternativeName{
			Type: x509util.EmailType, Value: emailAddress,
		}.RawValue()
		if err != nil {
			return zero, err
		}
		rawValues = append(rawValues, rawValue)
	}

	for _, ip := range ipAddresses {
		rawValue, err := x509util.SubjectAlternativeName{
			Type: x509util.IPType, Value: ip.String(),
		}.RawValue()
		if err != nil {
			return zero, err
		}
		rawValues = append(rawValues, rawValue)
	}

	for _, uri := range uris {
		rawValue, err := x509util.SubjectAlternativeName{
			Type: x509util.URIType, Value: uri.String(),
		}.RawValue()
		if err != nil {
			return zero, err
		}
		rawValues = append(rawValues, rawValue)
	}

	for _, san := range sans {
		rawValue, err := san.RawValue()
		if err != nil {
			return zero, err
		}
		rawValues = append(rawValues, rawValue)
	}

	// Now marshal the rawValues into the ASN1 sequence, and create an Extension object to hold the extension
	rawBytes, err := asn1.Marshal(rawValues)
	if err != nil {
		return zero, fmt.Errorf("error marshaling SubjectAlternativeName extension to ASN1: %w", err)
	}

	return x509util.Extension{
		ID:       x509util.ObjectIdentifier(oidSubjectAlternativeName),
		Critical: subjectIsEmpty,
		Value:    rawBytes,
	}, nil
}
