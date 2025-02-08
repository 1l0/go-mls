package mls

import (
	"golang.org/x/crypto/cryptobyte"
)

type RatchetLabel []byte

var (
	RatchetLabelHandshake   = RatchetLabel("handshake")
	RatchetLabelApplication = RatchetLabel("application")
)

func RatchetLabelFromContentType(ct contentType) RatchetLabel {
	switch ct {
	case contentTypeApplication:
		return RatchetLabelApplication
	case contentTypeProposal, contentTypeCommit:
		return RatchetLabelHandshake
	default:
		panic("unreachable")
	}
}

// SecretTree holds tree node secrets used for the generation of encryption
// keys and nonces.
type SecretTree [][]byte

func DeriveSecretTree(cs CipherSuite, n NumLeaves, encryptionSecret []byte) (SecretTree, error) {
	tree := make(SecretTree, int(n.Width()))
	tree.Set(n.Root(), encryptionSecret)
	err := tree.DeriveChildren(cs, n.Root())
	return tree, err
}

func (tree SecretTree) DeriveChildren(cs CipherSuite, x NodeIndex) error {
	l, r, ok := x.Children()
	if !ok {
		return nil
	}

	parentSecret := tree.Get(x)
	_, kdf, _ := cs.HPKE().Params()
	nh := uint16(kdf.ExtractSize())
	leftSecret, err := cs.ExpandWithLabel(parentSecret, []byte("tree"), []byte("left"), nh)
	if err != nil {
		return err
	}
	rightSecret, err := cs.ExpandWithLabel(parentSecret, []byte("tree"), []byte("right"), nh)
	if err != nil {
		return err
	}

	tree.Set(l, leftSecret)
	tree.Set(r, rightSecret)

	if err := tree.DeriveChildren(cs, l); err != nil {
		return err
	}
	if err := tree.DeriveChildren(cs, r); err != nil {
		return err
	}

	return nil
}

func (tree SecretTree) Get(ni NodeIndex) []byte {
	secret := tree[int(ni)]
	if secret == nil {
		panic("empty node in secret tree")
	}
	return secret
}

func (tree SecretTree) Set(ni NodeIndex, secret []byte) {
	tree[int(ni)] = secret
}

// DeriveRatchetRoot derives the root of a ratchet for a tree node.
func (tree SecretTree) DeriveRatchetRoot(cs CipherSuite, ni NodeIndex, label RatchetLabel) (RatchetSecret, error) {
	_, kdf, _ := cs.HPKE().Params()
	nh := uint16(kdf.ExtractSize())
	root, err := cs.ExpandWithLabel(tree.Get(ni), []byte(label), nil, nh)
	return RatchetSecret{root, 0}, err
}

type RatchetSecret struct {
	Secret     []byte
	Generation uint32
}

func (secret RatchetSecret) DeriveNonce(cs CipherSuite) ([]byte, error) {
	_, _, aead := cs.HPKE().Params()
	nn := uint16(aead.NonceSize())
	return DeriveTreeSecret(cs, secret.Secret, []byte("nonce"), secret.Generation, nn)
}

func (secret RatchetSecret) DeriveKey(cs CipherSuite) ([]byte, error) {
	_, _, aead := cs.HPKE().Params()
	nk := uint16(aead.KeySize())
	return DeriveTreeSecret(cs, secret.Secret, []byte("key"), secret.Generation, nk)
}

func (secret RatchetSecret) DeriveNext(cs CipherSuite) (RatchetSecret, error) {
	_, kdf, _ := cs.HPKE().Params()
	nh := uint16(kdf.ExtractSize())
	next, err := DeriveTreeSecret(cs, secret.Secret, []byte("secret"), secret.Generation, nh)
	return RatchetSecret{next, secret.Generation + 1}, err
}

func DeriveTreeSecret(cs CipherSuite, secret, label []byte, generation uint32, length uint16) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint32(generation)
	context := b.BytesOrPanic()

	return cs.ExpandWithLabel(secret, label, context, length)
}
