package device

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/jessepeterson/cfgprofiles"
	"go.step.sm/crypto/minica"
)

func Test_createACMECSR(t *testing.T) {
	device := &Device{}
	payloadWithoutSubjectAltName := &cfgprofiles.ACMECertificatePayload{
		Payload: cfgprofiles.Payload{
			PayloadIdentifier: "com.apple.security.acme.cbdc6238-feec-4171-8784-98e576bbb814",
			PayloadUUID:       "cbdc6238-feec-4171-8784-98e576bbb814",
			PayloadType:       "com.apple.security.acme",
			PayloadVersion:    1,
		},
		Attest:           true,
		ClientIdentifier: "2678F47F-7A0B-4E7E-BEBC-29C1DCAF28C6",
		DirectoryURL:     "https://127.0.0.1:8443/acme/appleacmesim/directory",
		ExtendedKeyUsage: []string{
			"1.3.6.1.5.5.7.3.2",
		},
		HardwareBound:    true,
		KeyIsExtractable: nil,
		KeyType:          "ECSECPrimeRandom",
		KeySize:          384,
		Subject: [][][]string{
			{
				[]string{
					"C", "NL",
				},
			},
			{
				[]string{
					"O", "Smallstep ACME DA Demo",
				},
			},
		},
		UsageFlags: 0,
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	fatalIf(t, err)
	compFunc := func(csr *x509.CertificateRequest) (err error) {
		if err = csr.CheckSignature(); err != nil {
			return
		}
		if csr.Subject.CommonName != "" {
			return errors.New("expected Subject Common Name to be empty")
		}
		if csr.Subject.Organization[0] != "Smallstep ACME DA Demo" {
			return fmt.Errorf("expected Subject Organization to be %q", "Smallstep ACME DA Demo")
		}
		if csr.Subject.Country[0] != "NL" {
			return fmt.Errorf("expected Subject Country to be %q", "NL")
		}

		// testing (extended) key usage extension to exist in the CSR is (currently) done
		// by signing the CSR and inspecting the certificate instead, because the values
		// aren't easily inspectable with just the CSR. Downside of this approach is that
		// the CA can determine what's actually set in the certificate.

		lt := `{
			"subject": {{ toJson .Subject }},
			"sans": {{ toJson .SANs }},
		{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
			"keyUsage": ["keyEncipherment", "digitalSignature"],
		{{- else }}
			"keyUsage": ["digitalSignature"],
		{{- end }}
			"extKeyUsage": ["clientAuth"]
		}` // NOTE: this template affects what ends up in the tested certificate

		ca, err := minica.New()
		fatalIf(t, err)

		cert, err := ca.SignCSR(csr, minica.WithTemplate(lt))
		fatalIf(t, err)

		expectedKeyUsage := x509.KeyUsageDigitalSignature
		if cert.KeyUsage != expectedKeyUsage {
			return fmt.Errorf("expected %v, got %v", expectedKeyUsage, cert.KeyUsage)
		}

		expectedExtendedKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		if !reflect.DeepEqual(cert.ExtKeyUsage, expectedExtendedKeyUsage) {
			return fmt.Errorf("expected %v, got %v", expectedExtendedKeyUsage, cert.ExtKeyUsage)
		}

		return nil
	}
	type args struct {
		device *Device
		pl     *cfgprofiles.ACMECertificatePayload
		key    crypto.Signer
	}
	tests := []struct {
		name     string
		args     args
		compFunc func(csr *x509.CertificateRequest) error
		wantErr  bool
	}{
		{"ok", args{device: device, pl: payloadWithoutSubjectAltName, key: key}, compFunc, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createACMECSR(tt.args.device, tt.args.pl, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("createACMECSR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err := compFunc(got); err != nil {
				t.Errorf("failed comparing resulting CSR: %v", err)
			}
		})
	}
}

func fatalIf(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}
