package mls

import (
	"bytes"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

type KeyPackage struct {
	Version     ProtocolVersion
	CipherSuite CipherSuite
	InitKey     HPKEPublicKey
	LeafNode    LeafNode
	Extensions  []Extension
	Signature   []byte
}

func (pkg *KeyPackage) Unmarshal(s *cryptobyte.String) error {
	*pkg = KeyPackage{}

	ok := s.ReadUint16((*uint16)(&pkg.Version)) &&
		s.ReadUint16((*uint16)(&pkg.CipherSuite)) &&
		ReadOpaqueVec(s, (*[]byte)(&pkg.InitKey))
	if !ok {
		return io.ErrUnexpectedEOF
	}

	if err := pkg.LeafNode.Unmarshal(s); err != nil {
		return err
	}

	exts, err := UnmarshalExtensionVec(s)
	if err != nil {
		return err
	}
	pkg.Extensions = exts

	if !ReadOpaqueVec(s, &pkg.Signature) {
		return err
	}

	return nil
}

func (pkg *KeyPackage) marshalTBS(b *cryptobyte.Builder) {
	b.AddUint16(uint16(pkg.Version))
	b.AddUint16(uint16(pkg.CipherSuite))
	WriteOpaqueVec(b, []byte(pkg.InitKey))
	pkg.LeafNode.Marshal(b)
	MarshalExtensionVec(b, pkg.Extensions)
}

func (pkg *KeyPackage) Marshal(b *cryptobyte.Builder) {
	pkg.marshalTBS(b)
	WriteOpaqueVec(b, pkg.Signature)
}

func (pkg *KeyPackage) verifySignature() bool {
	var b cryptobyte.Builder
	pkg.marshalTBS(&b)
	rawTBS, err := b.Bytes()
	if err != nil {
		return false
	}

	return pkg.CipherSuite.VerifyWithLabel(pkg.LeafNode.signatureKey, []byte("KeyPackageTBS"), rawTBS, pkg.Signature)
}

// Verify performs KeyPackage verification as described in RFC 9420 section 10.1.
func (pkg *KeyPackage) Verify(ctx *GroupContext) error {
	if pkg.Version != ctx.Version {
		return fmt.Errorf("mls: key package version doesn't match group context")
	}
	if pkg.CipherSuite != ctx.CipherSuite {
		return fmt.Errorf("mls: cipher suite doesn't match group context")
	}
	if pkg.LeafNode.leafNodeSource != LeafNodeSourceKeyPackage {
		return fmt.Errorf("mls: key package contains a leaf node with an invalid source")
	}
	if !pkg.verifySignature() {
		return fmt.Errorf("mls: invalid key package signature")
	}
	if bytes.Equal(pkg.LeafNode.encryptionKey, pkg.InitKey) {
		return fmt.Errorf("mls: key package encryption key and init key are identical")
	}
	return nil
}

func (pkg *KeyPackage) GenerateRef() (keyPackageRef, error) {
	var b cryptobyte.Builder
	pkg.Marshal(&b)
	raw, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	hash, err := pkg.CipherSuite.refHash([]byte("MLS 1.0 KeyPackage Reference"), raw)
	if err != nil {
		return nil, err
	}

	return keyPackageRef(hash), nil
}

type keyPackageRef []byte

func (ref keyPackageRef) Equal(other keyPackageRef) bool {
	return bytes.Equal([]byte(ref), []byte(other))
}
