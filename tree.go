package mls

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

type ParentNode struct {
	encryptionKey  HPKEPublicKey
	parentHash     []byte
	unmergedLeaves []leafIndex
}

func (node *ParentNode) Unmarshal(s *cryptobyte.String) error {
	*node = ParentNode{}
	if !ReadOpaqueVec(s, (*[]byte)(&node.encryptionKey)) || !ReadOpaqueVec(s, &node.parentHash) {
		return io.ErrUnexpectedEOF
	}
	return ReadVector(s, func(s *cryptobyte.String) error {
		var i leafIndex
		if !s.ReadUint32((*uint32)(&i)) {
			return io.ErrUnexpectedEOF
		}
		node.unmergedLeaves = append(node.unmergedLeaves, i)
		return nil
	})
}

func (node *ParentNode) Marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, []byte(node.encryptionKey))
	WriteOpaqueVec(b, node.parentHash)
	WriteVector(b, len(node.unmergedLeaves), func(b *cryptobyte.Builder, i int) {
		b.AddUint32(uint32(node.unmergedLeaves[i]))
	})
}

func (node *ParentNode) ComputeParentHash(cs CipherSuite, originalSiblingTreeHash []byte) ([]byte, error) {
	rawInput, err := MarshalParentHashInput(node.encryptionKey, node.parentHash, originalSiblingTreeHash)
	if err != nil {
		return nil, err
	}
	h := cs.hash().New()
	h.Write(rawInput)
	return h.Sum(nil), nil
}

func MarshalParentHashInput(encryptionKey HPKEPublicKey, parentHash, originalSiblingTreeHash []byte) ([]byte, error) {
	var b cryptobyte.Builder
	WriteOpaqueVec(&b, []byte(encryptionKey))
	WriteOpaqueVec(&b, parentHash)
	WriteOpaqueVec(&b, originalSiblingTreeHash)
	return b.Bytes()
}

type LeafNodeSource uint8

const (
	LeafNodeSourceKeyPackage LeafNodeSource = 1
	LeafNodeSourceUpdate     LeafNodeSource = 2
	LeafNodeSourceCommit     LeafNodeSource = 3
)

func (src *LeafNodeSource) Unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint8((*uint8)(src)) {
		return io.ErrUnexpectedEOF
	}
	switch *src {
	case LeafNodeSourceKeyPackage, LeafNodeSourceUpdate, LeafNodeSourceCommit:
		return nil
	default:
		return fmt.Errorf("mls: invalid leaf node source %d", *src)
	}
}

func (src LeafNodeSource) Marshal(b *cryptobyte.Builder) {
	b.AddUint8(uint8(src))
}

type Capabilities struct {
	Versions     []ProtocolVersion
	CipherSuites []CipherSuite
	Extensions   []ExtensionType
	Proposals    []ProposalType
	Credentials  []CredentialType
}

func (caps *Capabilities) Unmarshal(s *cryptobyte.String) error {
	*caps = Capabilities{}

	// Note: all unknown values here must be ignored

	err := ReadVector(s, func(s *cryptobyte.String) error {
		var ver ProtocolVersion
		if !s.ReadUint16((*uint16)(&ver)) {
			return io.ErrUnexpectedEOF
		}
		caps.Versions = append(caps.Versions, ver)
		return nil
	})
	if err != nil {
		return err
	}

	err = ReadVector(s, func(s *cryptobyte.String) error {
		var cs CipherSuite
		if !s.ReadUint16((*uint16)(&cs)) {
			return io.ErrUnexpectedEOF
		}
		caps.CipherSuites = append(caps.CipherSuites, cs)
		return nil
	})
	if err != nil {
		return err
	}

	err = ReadVector(s, func(s *cryptobyte.String) error {
		var et ExtensionType
		if !s.ReadUint16((*uint16)(&et)) {
			return io.ErrUnexpectedEOF
		}
		caps.Extensions = append(caps.Extensions, et)
		return nil
	})
	if err != nil {
		return err
	}

	err = ReadVector(s, func(s *cryptobyte.String) error {
		var pt ProposalType
		if !s.ReadUint16((*uint16)(&pt)) {
			return io.ErrUnexpectedEOF
		}
		caps.Proposals = append(caps.Proposals, pt)
		return nil
	})
	if err != nil {
		return err
	}

	err = ReadVector(s, func(s *cryptobyte.String) error {
		var ct CredentialType
		if !s.ReadUint16((*uint16)(&ct)) {
			return io.ErrUnexpectedEOF
		}
		caps.Credentials = append(caps.Credentials, ct)
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (caps *Capabilities) Marshal(b *cryptobyte.Builder) {
	WriteVector(b, len(caps.Versions), func(b *cryptobyte.Builder, i int) {
		b.AddUint16(uint16(caps.Versions[i]))
	})

	WriteVector(b, len(caps.CipherSuites), func(b *cryptobyte.Builder, i int) {
		b.AddUint16(uint16(caps.CipherSuites[i]))
	})

	WriteVector(b, len(caps.Extensions), func(b *cryptobyte.Builder, i int) {
		b.AddUint16(uint16(caps.Extensions[i]))
	})

	WriteVector(b, len(caps.Proposals), func(b *cryptobyte.Builder, i int) {
		b.AddUint16(uint16(caps.Proposals[i]))
	})

	WriteVector(b, len(caps.Credentials), func(b *cryptobyte.Builder, i int) {
		b.AddUint16(uint16(caps.Credentials[i]))
	})
}

const MaxLeafNodeLifetime = 3 * 30 * 24 * time.Hour

type Lifetime struct {
	notBefore, notAfter uint64
}

func (lt *Lifetime) Unmarshal(s *cryptobyte.String) error {
	*lt = Lifetime{}
	if !s.ReadUint64(&lt.notBefore) || !s.ReadUint64(&lt.notAfter) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (lt *Lifetime) Marshal(b *cryptobyte.Builder) {
	b.AddUint64(lt.notBefore)
	b.AddUint64(lt.notAfter)
}

func (lt *Lifetime) NotBeforeTime() time.Time {
	return time.Unix(int64(lt.notBefore), 0)
}

func (lt *Lifetime) NotAfterTime() time.Time {
	return time.Unix(int64(lt.notAfter), 0)
}

// Verify ensures that the lifetime is valid: it has an acceptable range and
// the current time is within that range.
func (lt *Lifetime) Verify(t time.Time) bool {
	notBefore, notAfter := lt.NotBeforeTime(), lt.NotAfterTime()

	if d := notAfter.Sub(notBefore); d <= 0 || d > MaxLeafNodeLifetime {
		return false
	}

	return t.After(notBefore) && notAfter.After(t)
}

type ExtensionType uint16

// http://www.iana.org/assignments/mls/mls.xhtml#mls-extension-types
const (
	ExtensionTypeApplicationID        ExtensionType = 0x0001
	ExtensionTypeRatchetTree          ExtensionType = 0x0002
	ExtensionTypeRequiredCapabilities ExtensionType = 0x0003
	ExtensionTypeExternalPub          ExtensionType = 0x0004
	ExtensionTypeExternalSenders      ExtensionType = 0x0005
)

type Extension struct {
	ExtensionType ExtensionType
	ExtensionData []byte
}

func UnmarshalExtensionVec(s *cryptobyte.String) ([]Extension, error) {
	var exts []Extension
	err := ReadVector(s, func(s *cryptobyte.String) error {
		var ext Extension
		if !s.ReadUint16((*uint16)(&ext.ExtensionType)) || !ReadOpaqueVec(s, &ext.ExtensionData) {
			return io.ErrUnexpectedEOF
		}
		exts = append(exts, ext)
		return nil
	})
	return exts, err
}

func MarshalExtensionVec(b *cryptobyte.Builder, exts []Extension) {
	WriteVector(b, len(exts), func(b *cryptobyte.Builder, i int) {
		ext := exts[i]
		b.AddUint16(uint16(ext.ExtensionType))
		WriteOpaqueVec(b, ext.ExtensionData)
	})
}

func FindExtensionData(exts []Extension, t ExtensionType) []byte {
	for _, ext := range exts {
		if ext.ExtensionType == t {
			return ext.ExtensionData
		}
	}
	return nil
}

type LeafNode struct {
	encryptionKey HPKEPublicKey
	signatureKey  SignaturePublicKey
	credential    Credential
	capabilities  Capabilities

	leafNodeSource LeafNodeSource
	lifetime       *Lifetime // for leafNodeSourceKeyPackage
	parentHash     []byte    // for leafNodeSourceCommit

	extensions []Extension
	signature  []byte
}

func (node *LeafNode) Unmarshal(s *cryptobyte.String) error {
	*node = LeafNode{}

	if !ReadOpaqueVec(s, (*[]byte)(&node.encryptionKey)) || !ReadOpaqueVec(s, (*[]byte)(&node.signatureKey)) {
		return io.ErrUnexpectedEOF
	}

	if err := node.credential.Unmarshal(s); err != nil {
		return err
	}
	if err := node.capabilities.Unmarshal(s); err != nil {
		return err
	}
	if err := node.leafNodeSource.Unmarshal(s); err != nil {
		return err
	}

	var err error
	switch node.leafNodeSource {
	case LeafNodeSourceKeyPackage:
		node.lifetime = new(Lifetime)
		err = node.lifetime.Unmarshal(s)
	case LeafNodeSourceCommit:
		if !ReadOpaqueVec(s, &node.parentHash) {
			err = io.ErrUnexpectedEOF
		}
	}
	if err != nil {
		return err
	}

	exts, err := UnmarshalExtensionVec(s)
	if err != nil {
		return err
	}
	node.extensions = exts

	if !ReadOpaqueVec(s, &node.signature) {
		return io.ErrUnexpectedEOF
	}

	return nil
}

func (node *LeafNode) marshalBase(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, []byte(node.encryptionKey))
	WriteOpaqueVec(b, []byte(node.signatureKey))
	node.credential.Marshal(b)
	node.capabilities.Marshal(b)
	node.leafNodeSource.Marshal(b)
	switch node.leafNodeSource {
	case LeafNodeSourceKeyPackage:
		node.lifetime.Marshal(b)
	case LeafNodeSourceCommit:
		WriteOpaqueVec(b, node.parentHash)
	}
	MarshalExtensionVec(b, node.extensions)
}

func (node *LeafNode) Marshal(b *cryptobyte.Builder) {
	node.marshalBase(b)
	WriteOpaqueVec(b, []byte(node.signature))
}

type LeafNodeTBS struct {
	*LeafNode

	// for leafNodeSourceUpdate and leafNodeSourceCommit
	groupID   GroupID
	leafIndex leafIndex
}

func (node *LeafNodeTBS) Marshal(b *cryptobyte.Builder) {
	node.LeafNode.marshalBase(b)
	switch node.LeafNode.leafNodeSource {
	case LeafNodeSourceUpdate, LeafNodeSourceCommit:
		WriteOpaqueVec(b, []byte(node.groupID))
		b.AddUint32(uint32(node.leafIndex))
	}
}

// verifySignature verifies the signature of the leaf node.
//
// groupID and li can be left unspecified if the leaf node source is neither
// update nor commit.
func (node *LeafNode) verifySignature(cs CipherSuite, groupID GroupID, li leafIndex) bool {
	leafNodeTBS, err := Marshal(&LeafNodeTBS{
		LeafNode:  node,
		groupID:   groupID,
		leafIndex: li,
	})
	if err != nil {
		return false
	}
	return cs.VerifyWithLabel([]byte(node.signatureKey), []byte("LeafNodeTBS"), leafNodeTBS, node.signature)
}

// Verify performs leaf node validation described in section 7.3.
//
// It does not perform all checks: it does not check that the credential is
// valid.
func (node *LeafNode) Verify(options *LeafNodeVerifyOptions) error {
	li := options.leafIndex

	if !node.verifySignature(options.cipherSuite, options.groupID, li) {
		return fmt.Errorf("mls: leaf node signature verification failed")
	}

	// TODO: check required_capabilities group extension

	if _, ok := options.supportedCreds[node.credential.CredentialType]; !ok {
		return fmt.Errorf("mls: credential type %v used by leaf node not supported by all members", node.credential.CredentialType)
	}

	if node.lifetime != nil {
		now := options.now
		if now == nil {
			now = time.Now
		}
		if t := now(); !t.IsZero() && !node.lifetime.Verify(t) {
			return fmt.Errorf("mls: lifetime verification failed (not before %v, not after %v)", node.lifetime.NotBeforeTime(), node.lifetime.NotAfterTime())
		}
	}

	supportedExts := make(map[ExtensionType]struct{})
	for _, et := range node.capabilities.Extensions {
		supportedExts[et] = struct{}{}
	}
	for _, ext := range node.extensions {
		if _, ok := supportedExts[ext.ExtensionType]; !ok {
			return fmt.Errorf("mls: extension type %d used by leaf node not supported by that leaf node", ext.ExtensionType)
		}
	}

	if _, dup := options.signatureKeys[string(node.signatureKey)]; dup {
		return fmt.Errorf("mls: duplicate signature key in ratchet tree")
	}
	if _, dup := options.encryptionKeys[string(node.encryptionKey)]; dup {
		return fmt.Errorf("mls: duplicate encryption key in ratchet tree")
	}

	return nil
}

type LeafNodeVerifyOptions struct {
	cipherSuite    CipherSuite
	groupID        GroupID
	leafIndex      leafIndex
	supportedCreds map[CredentialType]struct{}
	signatureKeys  map[string]struct{}
	encryptionKeys map[string]struct{}
	now            func() time.Time
}

type UpdatePathNode struct {
	encryptionKey       HPKEPublicKey
	encryptedPathSecret []HPKECiphertext
}

func (node *UpdatePathNode) Unmarshal(s *cryptobyte.String) error {
	*node = UpdatePathNode{}

	if !ReadOpaqueVec(s, (*[]byte)(&node.encryptionKey)) {
		return io.ErrUnexpectedEOF
	}

	return ReadVector(s, func(s *cryptobyte.String) error {
		var ciphertext HPKECiphertext
		if err := ciphertext.unmarshal(s); err != nil {
			return err
		}
		node.encryptedPathSecret = append(node.encryptedPathSecret, ciphertext)
		return nil
	})
}

func (node *UpdatePathNode) Marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, []byte(node.encryptionKey))
	WriteVector(b, len(node.encryptedPathSecret), func(b *cryptobyte.Builder, i int) {
		node.encryptedPathSecret[i].marshal(b)
	})
}

func DecryptPathSecret(cs CipherSuite, nodePriv []byte, ctx *GroupContext, ciphertext HPKECiphertext) ([]byte, error) {
	rawCtx, err := Marshal(ctx)
	if err != nil {
		return nil, err
	}
	return cs.DecryptWithLabel(nodePriv, []byte("UpdatePathNode"), rawCtx, ciphertext.KEMOutput, ciphertext.Ciphertext)
}

func NodePrivFromPathSecret(cs CipherSuite, pathSecret []byte, nodePub HPKEPublicKey) ([]byte, error) {
	nodeSecret, err := cs.DeriveSecret(pathSecret, []byte("node"))
	if err != nil {
		return nil, err
	}
	kem, _, _ := cs.hpke().Params()
	pub, priv := kem.Scheme().DeriveKeyPair(nodeSecret)
	if b, err := pub.MarshalBinary(); err != nil {
		return nil, err
	} else if !bytes.Equal(b, nodePub) {
		return nil, fmt.Errorf("mls: node public key mismatch")
	}
	return priv.MarshalBinary()
}

type UpdatePath struct {
	leafNode LeafNode
	nodes    []UpdatePathNode
}

func (up *UpdatePath) Unmarshal(s *cryptobyte.String) error {
	*up = UpdatePath{}

	if err := up.leafNode.Unmarshal(s); err != nil {
		return err
	}

	return ReadVector(s, func(s *cryptobyte.String) error {
		var node UpdatePathNode
		if err := node.Unmarshal(s); err != nil {
			return err
		}
		up.nodes = append(up.nodes, node)
		return nil
	})
}

func (up *UpdatePath) Marshal(b *cryptobyte.Builder) {
	up.leafNode.Marshal(b)
	WriteVector(b, len(up.nodes), func(b *cryptobyte.Builder, i int) {
		up.nodes[i].Marshal(b)
	})
}

type NodeType uint8

const (
	NodeTypeLeaf   NodeType = 1
	NodeTypeParent NodeType = 2
)

func (t *NodeType) Unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint8((*uint8)(t)) {
		return io.ErrUnexpectedEOF
	}
	switch *t {
	case NodeTypeLeaf, NodeTypeParent:
		return nil
	default:
		return fmt.Errorf("mls: invalid node type %d", *t)
	}
}

func (t NodeType) Marshal(b *cryptobyte.Builder) {
	b.AddUint8(uint8(t))
}

type Node struct {
	nodeType   NodeType
	leafNode   *LeafNode   // for nodeTypeLeaf
	parentNode *ParentNode // for nodeTypeParent
}

func (n *Node) Unmarshal(s *cryptobyte.String) error {
	*n = Node{}

	if err := n.nodeType.Unmarshal(s); err != nil {
		return err
	}

	switch n.nodeType {
	case NodeTypeLeaf:
		n.leafNode = new(LeafNode)
		return n.leafNode.Unmarshal(s)
	case NodeTypeParent:
		n.parentNode = new(ParentNode)
		return n.parentNode.Unmarshal(s)
	default:
		panic("unreachable")
	}
}

func (n *Node) Marshal(b *cryptobyte.Builder) {
	n.nodeType.Marshal(b)
	switch n.nodeType {
	case NodeTypeLeaf:
		n.leafNode.Marshal(b)
	case NodeTypeParent:
		n.parentNode.Marshal(b)
	default:
		panic("unreachable")
	}
}

func (n *Node) EncryptionKey() HPKEPublicKey {
	switch n.nodeType {
	case NodeTypeLeaf:
		return n.leafNode.encryptionKey
	case NodeTypeParent:
		return n.parentNode.encryptionKey
	default:
		panic("unreachable")
	}
}

type RatchetTree []*Node

func (tree *RatchetTree) Unmarshal(s *cryptobyte.String) error {
	*tree = RatchetTree{}
	err := ReadVector(s, func(s *cryptobyte.String) error {
		var n *Node
		var hasNode bool
		if !ReadOptional(s, &hasNode) {
			return io.ErrUnexpectedEOF
		} else if hasNode {
			n = new(Node)
			if err := n.Unmarshal(s); err != nil {
				return err
			}
		}
		*tree = append(*tree, n)
		return nil
	})
	if err != nil {
		return err
	}

	// The raw tree doesn't include blank nodes at the end, fill it until next
	// power of 2
	for !isPowerOf2(uint32(len(*tree) + 1)) {
		*tree = append(*tree, nil)
	}

	return nil
}

func (tree RatchetTree) Marshal(b *cryptobyte.Builder) {
	end := len(tree)
	for end > 0 && tree[end-1] == nil {
		end--
	}

	WriteVector(b, len(tree[:end]), func(b *cryptobyte.Builder, i int) {
		n := tree[i]
		WriteOptional(b, n != nil)
		if n != nil {
			n.Marshal(b)
		}
	})
}

// Get returns the node at the provided index.
//
// nil is returned for blank nodes. Get panics if the index is out of range.
func (tree RatchetTree) Get(i NodeIndex) *Node {
	return tree[int(i)]
}

func (tree RatchetTree) Set(i NodeIndex, node *Node) {
	tree[int(i)] = node
}

func (tree RatchetTree) GetLeaf(li leafIndex) *LeafNode {
	node := tree.Get(li.NodeIndex())
	if node == nil {
		return nil
	}
	if node.nodeType != NodeTypeLeaf {
		panic("unreachable")
	}
	return node.leafNode
}

// Resolve computes the resolution of a node.
func (tree RatchetTree) Resolve(x NodeIndex) []NodeIndex {
	n := tree.Get(x)
	if n == nil {
		l, r, ok := x.Children()
		if !ok {
			return nil // leaf
		}
		return append(tree.Resolve(l), tree.Resolve(r)...)
	} else {
		res := []NodeIndex{x}
		if n.nodeType == NodeTypeParent {
			for _, leafIndex := range n.parentNode.unmergedLeaves {
				res = append(res, leafIndex.NodeIndex())
			}
		}
		return res
	}
}

func (tree RatchetTree) SupportedCreds() map[CredentialType]struct{} {
	numMembers := 0
	supportedCredsCount := make(map[CredentialType]int)
	for li := leafIndex(0); li < leafIndex(tree.numLeaves()); li++ {
		node := tree.GetLeaf(li)
		if node == nil {
			continue
		}

		numMembers++
		for _, ct := range node.capabilities.Credentials {
			supportedCredsCount[ct]++
		}
	}

	supportedCreds := make(map[CredentialType]struct{})
	for ct, n := range supportedCredsCount {
		if n == numMembers {
			supportedCreds[ct] = struct{}{}
		}
	}

	return supportedCreds
}

func (tree RatchetTree) Keys() (signatureKeys, encryptionKeys map[string]struct{}) {
	signatureKeys = make(map[string]struct{})
	encryptionKeys = make(map[string]struct{})
	for li := leafIndex(0); li < leafIndex(tree.numLeaves()); li++ {
		node := tree.GetLeaf(li)
		if node == nil {
			continue
		}
		signatureKeys[string(node.signatureKey)] = struct{}{}
		encryptionKeys[string(node.encryptionKey)] = struct{}{}
	}
	return signatureKeys, encryptionKeys
}

// VerifyIntegrity verifies the integrity of the ratchet tree, as described in
// section 12.4.3.1.
//
// This function does not perform full leaf node validation. In particular:
//
//   - It doesn't check that credentials are valid.
//   - It doesn't check the lifetime field.
func (tree RatchetTree) VerifyIntegrity(ctx *GroupContext, now func() time.Time) error {
	cs := ctx.CipherSuite
	numLeaves := tree.numLeaves()

	if h, err := tree.ComputeRootTreeHash(cs); err != nil {
		return err
	} else if !bytes.Equal(h, ctx.TreeHash) {
		return fmt.Errorf("mls: tree hash verification failed")
	}

	if !tree.verifyParentHashes(cs) {
		return fmt.Errorf("mls: parent hashes verification failed")
	}

	supportedCreds := tree.SupportedCreds()
	signatureKeys := make(map[string]struct{})
	encryptionKeys := make(map[string]struct{})
	for li := leafIndex(0); li < leafIndex(numLeaves); li++ {
		node := tree.GetLeaf(li)
		if node == nil {
			continue
		}

		err := node.Verify(&LeafNodeVerifyOptions{
			cipherSuite:    cs,
			groupID:        ctx.GroupID,
			leafIndex:      li,
			supportedCreds: supportedCreds,
			signatureKeys:  signatureKeys,
			encryptionKeys: encryptionKeys,
			now:            now,
		})
		if err != nil {
			return fmt.Errorf("leaf node at index %v: %v", li, err)
		}

		signatureKeys[string(node.signatureKey)] = struct{}{}
		encryptionKeys[string(node.encryptionKey)] = struct{}{}
	}

	for i, node := range tree {
		if node == nil || node.nodeType != NodeTypeParent {
			continue
		}
		p := NodeIndex(i)
		for _, unmergedLeaf := range node.parentNode.unmergedLeaves {
			x := unmergedLeaf.NodeIndex()
			for {
				var ok bool
				if x, ok = numLeaves.Parent(x); !ok {
					return fmt.Errorf("mls: unmerged leaf %v is not a descendant of the parent node at index %v", unmergedLeaf, p)
				} else if x == p {
					break
				}

				intermediateNode := tree.Get(x)
				if intermediateNode != nil && !hasUnmergedLeaf(intermediateNode.parentNode, unmergedLeaf) {
					return fmt.Errorf("mls: non-blank intermediate node at index %v is missing unmerged leaf %v", x, unmergedLeaf)
				}
			}
		}

		if _, dup := encryptionKeys[string(node.parentNode.encryptionKey)]; dup {
			return fmt.Errorf("mls: duplicate encryption key in ratchet tree")
		}
		encryptionKeys[string(node.parentNode.encryptionKey)] = struct{}{}
	}

	return nil
}

func hasUnmergedLeaf(node *ParentNode, unmergedLeaf leafIndex) bool {
	for _, li := range node.unmergedLeaves {
		if li == unmergedLeaf {
			return true
		}
	}
	return false
}

func (tree RatchetTree) ComputeRootTreeHash(cs CipherSuite) ([]byte, error) {
	return tree.ComputeTreeHash(cs, tree.numLeaves().Root(), nil)
}

func (tree RatchetTree) ComputeTreeHash(cs CipherSuite, x NodeIndex, exclude map[leafIndex]struct{}) ([]byte, error) {
	n := tree.Get(x)

	var b cryptobyte.Builder
	if li, ok := x.LeafIndex(); ok {
		_, excluded := exclude[li]

		var l *LeafNode
		if n != nil && !excluded {
			l = n.leafNode
			if l == nil {
				panic("unreachable")
			}
		}

		marshalLeafNodeHashInput(&b, li, l)
	} else {
		left, right, ok := x.Children()
		if !ok {
			panic("unreachable")
		}

		leftHash, err := tree.ComputeTreeHash(cs, left, exclude)
		if err != nil {
			return nil, err
		}
		rightHash, err := tree.ComputeTreeHash(cs, right, exclude)
		if err != nil {
			return nil, err
		}

		var p *ParentNode
		if n != nil {
			p = n.parentNode
			if p == nil {
				panic("unreachable")
			}

			if len(p.unmergedLeaves) > 0 && len(exclude) > 0 {
				unmergedLeaves := make([]leafIndex, 0, len(p.unmergedLeaves))
				for _, li := range p.unmergedLeaves {
					if _, excluded := exclude[li]; !excluded {
						unmergedLeaves = append(unmergedLeaves, li)
					}
				}

				filteredParent := *p
				filteredParent.unmergedLeaves = unmergedLeaves
				p = &filteredParent
			}
		}

		marshalParentNodeHashInput(&b, p, leftHash, rightHash)
	}
	in, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	h := cs.hash().New()
	h.Write(in)
	return h.Sum(nil), nil
}

func marshalLeafNodeHashInput(b *cryptobyte.Builder, i leafIndex, node *LeafNode) {
	b.AddUint8(uint8(NodeTypeLeaf))
	b.AddUint32(uint32(i))
	WriteOptional(b, node != nil)
	if node != nil {
		node.Marshal(b)
	}
}

func marshalParentNodeHashInput(b *cryptobyte.Builder, node *ParentNode, leftHash, rightHash []byte) {
	b.AddUint8(uint8(NodeTypeParent))
	WriteOptional(b, node != nil)
	if node != nil {
		node.Marshal(b)
	}
	WriteOpaqueVec(b, leftHash)
	WriteOpaqueVec(b, rightHash)
}

func (tree RatchetTree) verifyParentHashes(cs CipherSuite) bool {
	for i, node := range tree {
		if node == nil {
			continue
		}

		x := NodeIndex(i)
		l, r, ok := x.Children()
		if !ok {
			continue
		}

		parentNode := node.parentNode
		exclude := make(map[leafIndex]struct{}, len(parentNode.unmergedLeaves))
		for _, li := range parentNode.unmergedLeaves {
			exclude[li] = struct{}{}
		}

		leftTreeHash, err := tree.ComputeTreeHash(cs, l, exclude)
		if err != nil {
			return false
		}
		rightTreeHash, err := tree.ComputeTreeHash(cs, r, exclude)
		if err != nil {
			return false
		}

		leftParentHash, err := parentNode.ComputeParentHash(cs, rightTreeHash)
		if err != nil {
			return false
		}
		rightParentHash, err := parentNode.ComputeParentHash(cs, leftTreeHash)
		if err != nil {
			return false
		}

		isLeftDescendant := tree.findParentHash(tree.Resolve(l), leftParentHash)
		isRightDescendant := tree.findParentHash(tree.Resolve(r), rightParentHash)
		if isLeftDescendant == isRightDescendant {
			return false
		}
	}
	return true
}

func (tree RatchetTree) findParentHash(nodeIndices []NodeIndex, parentHash []byte) bool {
	for _, x := range nodeIndices {
		node := tree.Get(x)
		if node == nil {
			continue
		}
		var h []byte
		switch node.nodeType {
		case NodeTypeLeaf:
			h = node.leafNode.parentHash
		case NodeTypeParent:
			h = node.parentNode.parentHash
		}
		if bytes.Equal(h, parentHash) {
			return true
		}
	}
	return false
}

func (tree RatchetTree) numLeaves() NumLeaves {
	return NumLeavesFromWidth(uint32(len(tree)))
}

func (tree RatchetTree) FindLeaf(node *LeafNode) (leafIndex, bool) {
	for li := leafIndex(0); li < leafIndex(tree.numLeaves()); li++ {
		n := tree.GetLeaf(li)
		if n == nil {
			continue
		}

		// Encryption keys are unique
		if !bytes.Equal(n.encryptionKey, node.encryptionKey) {
			continue
		}

		// Make sure both nodes are identical
		raw1, err1 := Marshal(node)
		raw2, err2 := Marshal(n)
		return li, err1 == nil && err2 == nil && bytes.Equal(raw1, raw2)
	}
	return 0, false
}

func (tree *RatchetTree) Add(leafNode *LeafNode) {
	li := leafIndex(0)
	var ni NodeIndex
	found := false
	for {
		ni = li.NodeIndex()
		if int(ni) >= len(*tree) {
			break
		}
		if tree.Get(ni) == nil {
			found = true
			break
		}
		li++
	}
	if !found {
		ni = NodeIndex(len(*tree) + 1)
		newLen := ((len(*tree) + 1) * 2) - 1
		for len(*tree) < newLen {
			*tree = append(*tree, nil)
		}
	}

	numLeaves := tree.numLeaves()
	p := ni
	for {
		var ok bool
		p, ok = numLeaves.Parent(p)
		if !ok {
			break
		}
		node := tree.Get(p)
		if node != nil {
			node.parentNode.unmergedLeaves = append(node.parentNode.unmergedLeaves, li)
		}
	}

	tree.Set(ni, &Node{
		nodeType: NodeTypeLeaf,
		leafNode: leafNode,
	})
}

func (tree RatchetTree) Update(li leafIndex, leafNode *LeafNode) {
	ni := li.NodeIndex()

	tree.Set(ni, &Node{
		nodeType: NodeTypeLeaf,
		leafNode: leafNode,
	})

	numLeaves := tree.numLeaves()
	for {
		var ok bool
		ni, ok = numLeaves.Parent(ni)
		if !ok {
			break
		}

		tree.Set(ni, nil)
	}
}

func (tree *RatchetTree) Remove(li leafIndex) {
	ni := li.NodeIndex()

	numLeaves := tree.numLeaves()
	for {
		tree.Set(ni, nil)

		var ok bool
		ni, ok = numLeaves.Parent(ni)
		if !ok {
			break
		}
	}

	li = leafIndex(numLeaves - 1)
	lastPowerOf2 := len(*tree)
	for {
		ni = li.NodeIndex()
		if tree.Get(ni) != nil {
			break
		}

		if isPowerOf2(uint32(ni)) {
			lastPowerOf2 = int(ni)
		}

		if li == 0 {
			*tree = nil
			return
		}
		li--
	}

	if lastPowerOf2 < len(*tree) {
		*tree = (*tree)[:lastPowerOf2]
	}
}

func (tree RatchetTree) FilteredDirectPath(x NodeIndex) []NodeIndex {
	numLeaves := tree.numLeaves()

	var path []NodeIndex
	for {
		p, ok := numLeaves.Parent(x)
		if !ok {
			break
		}

		s, ok := numLeaves.Sibling(x)
		if !ok {
			panic("unreachable")
		}

		if len(tree.Resolve(s)) > 0 {
			path = append(path, p)
		}

		x = p
	}

	return path
}

func (tree RatchetTree) MergeUpdatePath(cs CipherSuite, senderLeafIndex leafIndex, path *UpdatePath) error {
	senderNodeIndex := senderLeafIndex.NodeIndex()
	numLeaves := tree.numLeaves()

	directPath := numLeaves.DirectPath(senderNodeIndex)
	for _, ni := range directPath {
		tree.Set(ni, nil)
	}

	filteredDirectPath := tree.FilteredDirectPath(senderNodeIndex)
	if len(filteredDirectPath) != len(path.nodes) {
		return fmt.Errorf("mls: UpdatePath has %v nodes, but filtered direct path has %v nodes", len(path.nodes), len(filteredDirectPath))
	}
	for i, ni := range filteredDirectPath {
		pathNode := path.nodes[i]
		tree.Set(ni, &Node{
			nodeType: NodeTypeParent,
			parentNode: &ParentNode{
				encryptionKey: pathNode.encryptionKey,
			},
		})
	}

	// Compute parent hashes, from root to leaf
	var prevParentHash []byte
	for i := len(filteredDirectPath) - 1; i >= 0; i-- {
		ni := filteredDirectPath[i]
		node := tree.Get(ni).parentNode

		l, r, ok := ni.Children()
		if !ok {
			panic("unreachable")
		}

		s := l
		found := false
		for _, ni := range directPath {
			if ni == s {
				found = true
				break
			}
		}
		if s == senderNodeIndex || found {
			s = r
		}

		treeHash, err := tree.ComputeTreeHash(cs, s, nil)
		if err != nil {
			return err
		}

		node.parentHash = prevParentHash
		h, err := node.ComputeParentHash(cs, treeHash)
		if err != nil {
			return err
		}
		prevParentHash = h
	}

	if !bytes.Equal(path.leafNode.parentHash, prevParentHash) {
		return fmt.Errorf("mls: parent hash mismatch for update path's leaf node")
	}

	tree.Set(senderNodeIndex, &Node{
		nodeType: NodeTypeLeaf,
		leafNode: &path.leafNode,
	})

	return nil
}

func (tree RatchetTree) DecryptPathSecrets(cs CipherSuite, groupCtx *GroupContext, senderLeafIndex, recipientLeafIndex leafIndex, path *UpdatePath, privTree [][]byte) ([]byte, error) {
	senderNodeIndex := senderLeafIndex.NodeIndex()
	recipientNodeIndex := recipientLeafIndex.NodeIndex()

	senderFilteredDirectPath := tree.FilteredDirectPath(senderNodeIndex)
	if len(path.nodes) != len(senderFilteredDirectPath) {
		return nil, fmt.Errorf("mls: invalid UpdatePath length")
	}

	// Identify a node in the filtered direct path for which the recipient is
	// in the subtree of the non-updated child
	recipientAncestorIndex := -1
	recipientAncestor := CommonAncestor(senderNodeIndex, recipientNodeIndex)
	for i, ni := range senderFilteredDirectPath {
		if ni == recipientAncestor {
			recipientAncestorIndex = i
			break
		}
	}
	if recipientAncestorIndex < 0 {
		return nil, fmt.Errorf("mls: cannot find recipient ancestor")
	}
	updatePathNode := path.nodes[recipientAncestorIndex]

	// Find the copath node
	ancestor := CommonAncestor(senderNodeIndex, recipientNodeIndex)
	var (
		copathNode NodeIndex
		ok         bool
	)
	if recipientNodeIndex < senderNodeIndex {
		copathNode, ok = ancestor.Left()
	} else {
		copathNode, ok = ancestor.Right()
	}
	if !ok {
		panic("unreachable")
	}

	copathResolution := tree.Resolve(copathNode)
	if len(updatePathNode.encryptedPathSecret) != len(copathResolution) {
		return nil, fmt.Errorf("mls: invalid UpdatePathNode.encrypted_path_secret length")
	}

	// Identify a node in the resolution of the copath node for which we have
	// a private key
	var nodePriv []byte
	resolutionIndex := -1
	for i, ni := range copathResolution {
		if p := privTree[int(ni)]; p != nil {
			nodePriv = p
			resolutionIndex = i
			break
		}
	}
	if nodePriv == nil {
		return nil, fmt.Errorf("mls: no private key found")
	}
	ciphertext := updatePathNode.encryptedPathSecret[resolutionIndex]

	// Decrypt the path secret using the private key from the resolution node
	pathSecret, err := DecryptPathSecret(cs, nodePriv, groupCtx, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt path secret: %v", err)
	}
	nodePub := tree.Get(recipientAncestor).EncryptionKey()
	nodePriv, err = NodePrivFromPathSecret(cs, pathSecret, nodePub)
	if err != nil {
		return nil, fmt.Errorf("failed to derive node %v private key from path secret: %v", recipientAncestor, err)
	}
	privTree[int(recipientAncestor)] = nodePriv

	// Derive path secrets for ancestors of that node in the sender's filtered
	// direct path
	for _, ni := range senderFilteredDirectPath[recipientAncestorIndex+1:] {
		pathSecret, err = cs.DeriveSecret(pathSecret, []byte("path"))
		if err != nil {
			return nil, fmt.Errorf("failed to derive path secret: %v", err)
		}
		nodePriv, err := NodePrivFromPathSecret(cs, pathSecret, tree.Get(ni).EncryptionKey())
		if err != nil {
			return nil, fmt.Errorf("failed to derive node %v private key from path secret: %v", ni, err)
		}
		privTree[int(ni)] = nodePriv
	}

	commitSecret, err := cs.DeriveSecret(pathSecret, []byte("path"))
	if err != nil {
		return nil, fmt.Errorf("failed to derive commit secret: %v", err)
	}

	return commitSecret, nil
}

func (tree *RatchetTree) Apply(proposals []Proposal, senders []leafIndex) {
	// Apply all update proposals
	for i, prop := range proposals {
		if prop.proposalType == ProposalTypeUpdate {
			tree.Update(senders[i], &prop.update.leafNode)
		}
	}

	// Apply all remove proposals
	for _, prop := range proposals {
		if prop.proposalType == ProposalTypeRemove {
			tree.Remove(prop.remove.removed)
		}
	}

	// Apply all add proposals
	for _, prop := range proposals {
		if prop.proposalType == ProposalTypeAdd {
			tree.Add(&prop.add.keyPackage.LeafNode)
		}
	}
}
