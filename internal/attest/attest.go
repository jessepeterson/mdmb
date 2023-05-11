package attest

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
)

type CA struct {
	m *minica.CA
}

func New(caCertFile, caKeyFile, caKeyPassword string) (*CA, error) {
	// (fake) attestation CA configuration is optional. If no signing certificate or
	// key is provided, assume no attestation CA is required and return early.
	if caCertFile == "" || caKeyFile == "" {
		return nil, nil
	}

	caCert, err := pemutil.ReadCertificate(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed reading ca certificate: %w", err)
	}

	anySigner, err := pemutil.Read(caKeyFile, pemutil.WithPassword([]byte(caKeyPassword)))
	if err != nil {
		return nil, fmt.Errorf("failed reading ca key: %w", err)
	}

	caSigner, ok := anySigner.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key read from %q is not a signer", caKeyFile)
	}

	ca := &CA{
		m: &minica.CA{
			Intermediate: caCert,
			Signer:       caSigner,
		},
	}

	return ca, nil
}

func (ca *CA) Sign(template *x509.Certificate) ([]*x509.Certificate, error) {
	cert, err := ca.m.Sign(template)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}
	return []*x509.Certificate{cert, ca.m.Intermediate}, nil
}
