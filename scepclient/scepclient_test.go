package scepclient

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"os"
	"testing"

	"github.com/smallstep/scep/x509util"
)

func TestExample(t *testing.T) {
	c, err := New("https://www.jessepeterson.space/scep")
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	_, err = c.GetCACaps(ctx)
	if err != nil {
		t.Fatal(err)
	}

	certs, err := c.GetCACert(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(certs) < 1 {
		t.Error("less than 1 cert")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := makeCSR(rand.Reader, "", key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := c.Sign(ctx, csr, nil)
	if err != nil {
		t.Fatal(err)
	}

	if cert == nil {
		t.Error("nil cert")
	} else {
		err = os.WriteFile("cert.out", cert.Raw, 0666)
		if err != nil {
			t.Fatal(err)
		}
	}

}

func makeCSR(rand io.Reader, challenge string, key crypto.PrivateKey) (*x509.CertificateRequest, error) {
	subject := pkix.Name{
		CommonName: "SCEP CSR",
	}
	tmpl := x509util.CertificateRequest{
		CertificateRequest: x509.CertificateRequest{
			Subject:            subject,
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
	}
	tmpl.ChallengePassword = challenge
	derBytes, err := x509util.CreateCertificateRequest(rand, &tmpl, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(derBytes)
}
