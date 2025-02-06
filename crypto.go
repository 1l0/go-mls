package mls

import (
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

type (
	HPKEPublicKey      []byte
	SignaturePublicKey []byte
)

type CredentialType uint16

// https://www.iana.org/assignments/mls/mls.xhtml#mls-credential-types
const (
	CredentialTypeBasic CredentialType = 0x0001
	CredentialTypeX509  CredentialType = 0x0002
)

type Credential struct {
	CredentialType CredentialType
	Identity       []byte   // for credentialTypeBasic
	Certificates   [][]byte // for credentialTypeX509
}

func (cred *Credential) Unmarshal(s *cryptobyte.String) error {
	*cred = Credential{}

	if !s.ReadUint16((*uint16)(&cred.CredentialType)) {
		return io.ErrUnexpectedEOF
	}

	switch cred.CredentialType {
	case CredentialTypeBasic:
		if !ReadOpaqueVec(s, &cred.Identity) {
			return io.ErrUnexpectedEOF
		}
		return nil
	case CredentialTypeX509:
		return ReadVector(s, func(s *cryptobyte.String) error {
			var cert []byte
			if !ReadOpaqueVec(s, &cert) {
				return io.ErrUnexpectedEOF
			}
			cred.Certificates = append(cred.Certificates, cert)
			return nil
		})
	default:
		return fmt.Errorf("mls: invalid credential type %d", cred.CredentialType)
	}
}

func (cred *Credential) Marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(cred.CredentialType))
	switch cred.CredentialType {
	case CredentialTypeBasic:
		WriteOpaqueVec(b, cred.Identity)
	case CredentialTypeX509:
		WriteVector(b, len(cred.Certificates), func(b *cryptobyte.Builder, i int) {
			WriteOpaqueVec(b, cred.Certificates[i])
		})
	default:
		panic("unreachable")
	}
}

type HPKECiphertext struct {
	KEMOutput  []byte
	Ciphertext []byte
}

func (hpke *HPKECiphertext) unmarshal(s *cryptobyte.String) error {
	*hpke = HPKECiphertext{}
	if !ReadOpaqueVec(s, &hpke.KEMOutput) || !ReadOpaqueVec(s, &hpke.Ciphertext) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (hpke *HPKECiphertext) marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, hpke.KEMOutput)
	WriteOpaqueVec(b, hpke.Ciphertext)
}
