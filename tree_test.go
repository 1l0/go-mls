package mls

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
	"time"
)

type treeValidationTest struct {
	CipherSuite CipherSuite `json:"cipher_suite"`

	Tree    testBytes `json:"tree"`
	GroupID testBytes `json:"group_id"`

	Resolutions [][]NodeIndex `json:"resolutions"`
	TreeHashes  []testBytes   `json:"tree_hashes"`
}

func testTreeValidation(t *testing.T, tc *treeValidationTest) {
	var tree RatchetTree
	if err := Unmarshal([]byte(tc.Tree), &tree); err != nil {
		t.Fatalf("unmarshal(tree) = %v", err)
	}

	for i, want := range tc.Resolutions {
		x := NodeIndex(i)
		res := tree.Resolve(x)
		if len(res) == 0 {
			res = make([]NodeIndex, 0)
		}
		if !reflect.DeepEqual(res, want) {
			t.Errorf("resolve(%v) = %v, want %v", x, res, want)
		}
	}

	for i, want := range tc.TreeHashes {
		x := NodeIndex(i)
		if h, err := tree.ComputeTreeHash(tc.CipherSuite, x, nil); err != nil {
			t.Errorf("computeTreeHash(%v) = %v", x, err)
		} else if !bytes.Equal(h, []byte(want)) {
			t.Errorf("computeTreeHash(%v) = %v, want %v", x, h, want)
		}
	}

	if !tree.verifyParentHashes(tc.CipherSuite) {
		t.Errorf("verifyParentHashes() failed")
	}

	groupID := GroupID(tc.GroupID)
	for i, node := range tree {
		if node == nil || node.nodeType != NodeTypeLeaf {
			continue
		}
		li, ok := NodeIndex(i).LeafIndex()
		if !ok {
			t.Errorf("leafIndex(%v) = false", i)
			continue
		}
		if !node.leafNode.verifySignature(tc.CipherSuite, groupID, li) {
			t.Errorf("verify(%v) = false", li)
		}
	}
}

func TestTreeValidation(t *testing.T) {
	var tests []treeValidationTest
	loadTestVector(t, "testdata/tree-validation.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testTreeValidation(t, &tc)
		})
	}
}

type treeKEMTest struct {
	CipherSuite CipherSuite `json:"cipher_suite"`

	GroupID                 testBytes `json:"group_id"`
	Epoch                   uint64    `json:"epoch"`
	ConfirmedTranscriptHash testBytes `json:"confirmed_transcript_hash"`

	RatchetTree testBytes `json:"ratchet_tree"`

	LeavesPrivate []struct {
		Index          leafIndex `json:"index"`
		EncryptionPriv testBytes `json:"encryption_priv"`
		SignaturePriv  testBytes `json:"signature_priv"`
		PathSecrets    []struct {
			Node       NodeIndex `json:"node"`
			PathSecret testBytes `json:"path_secret"`
		} `json:"path_secrets"`
	} `json:"leaves_private"`

	UpdatePaths []struct {
		Sender        leafIndex   `json:"sender"`
		UpdatePath    testBytes   `json:"update_path"`
		PathSecrets   []testBytes `json:"path_secrets"`
		CommitSecret  testBytes   `json:"commit_secret"`
		TreeHashAfter testBytes   `json:"tree_hash_after"`
	} `json:"update_paths"`
}

func testTreeKEM(t *testing.T, tc *treeKEMTest) {
	type privNode struct {
		encryptionPriv []byte
		signaturePriv  []byte
	}

	for _, leafPrivate := range tc.LeavesPrivate {
		var tree RatchetTree
		if err := Unmarshal([]byte(tc.RatchetTree), &tree); err != nil {
			t.Fatalf("unmarshal(ratchetTree) = %v", err)
		}

		privTree := make([]privNode, len(tree))
		privTree[int(leafPrivate.Index.NodeIndex())] = privNode{
			encryptionPriv: leafPrivate.EncryptionPriv,
			signaturePriv:  leafPrivate.SignaturePriv,
		}

		// TODO: drop the seed size check, see:
		// https://github.com/cloudflare/circl/issues/486
		kem, kdf, _ := tc.CipherSuite.hpke().Params()
		if kem.Scheme().SeedSize() != kdf.ExtractSize() {
			continue
		}

		for _, ps := range leafPrivate.PathSecrets {
			priv, err := NodePrivFromPathSecret(tc.CipherSuite, ps.PathSecret, tree.Get(ps.Node).EncryptionKey())
			if err != nil {
				t.Fatalf("failed to derive node %v private key from path secret: %v", ps.Node, err)
			}

			privTree[int(ps.Node)] = privNode{
				encryptionPriv: priv,
			}
		}

		for i, privNode := range privTree {
			if privNode.encryptionPriv == nil {
				continue
			}

			priv, err := kem.Scheme().UnmarshalBinaryPrivateKey(privNode.encryptionPriv)
			if err != nil {
				t.Fatalf("UnmarshalBinaryPrivateKey() = %v", err)
			}

			pub, err := kem.Scheme().UnmarshalBinaryPublicKey(tree[i].EncryptionKey())
			if err != nil {
				t.Fatalf("UnmarshalBinaryPublicKey() = %v", err)
			}

			if !priv.Public().Equal(pub) {
				t.Errorf("key pair mismatch for node %v", i)
			}

			// TODO: check signature key
		}
	}

	for _, updatePathTest := range tc.UpdatePaths {
		var tree RatchetTree
		if err := Unmarshal([]byte(tc.RatchetTree), &tree); err != nil {
			t.Fatalf("unmarshal(ratchetTree) = %v", err)
		}

		var up UpdatePath
		if err := Unmarshal([]byte(updatePathTest.UpdatePath), &up); err != nil {
			t.Fatalf("unmarshal(updatePath) = %v", err)
		}

		// TODO: verify that UpdatePath is parent-hash valid relative to ratchet tree
		// TODO: process UpdatePath using private leaves

		if err := tree.MergeUpdatePath(tc.CipherSuite, updatePathTest.Sender, &up); err != nil {
			t.Fatalf("ratchetTree.mergeUpdatePath() = %v", err)
		}

		treeHash, err := tree.ComputeRootTreeHash(tc.CipherSuite)
		if err != nil {
			t.Errorf("ratchetTree.computeRootTreeHash() = %v", err)
		} else if !bytes.Equal(treeHash, []byte(updatePathTest.TreeHashAfter)) {
			t.Errorf("ratchetTree.computeRootTreeHash() = %v, want %v", treeHash, updatePathTest.TreeHashAfter)
		}

		// TODO: create and verify new update path
	}
}

func TestTreeKEM(t *testing.T) {
	var tests []treeKEMTest
	loadTestVector(t, "testdata/treekem.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testTreeKEM(t, &tc)
		})
	}
}

type treeOperationsTest struct {
	CipherSuite CipherSuite `json:"cipher_suite"`

	TreeBefore     testBytes `json:"tree_before"`
	Proposal       testBytes `json:"proposal"`
	ProposalSender leafIndex `json:"proposal_sender"`

	TreeHashBefore testBytes `json:"tree_hash_before"`
	TreeAfter      testBytes `json:"tree_after"`
	TreeHashAfter  testBytes `json:"tree_hash_after"`
}

func testTreeOperations(t *testing.T, tc *treeOperationsTest) {
	var tree RatchetTree
	if err := Unmarshal([]byte(tc.TreeBefore), &tree); err != nil {
		t.Fatalf("unmarshal(tree) = %v", err)
	}

	treeHash, err := tree.ComputeRootTreeHash(tc.CipherSuite)
	if err != nil {
		t.Errorf("ratchetTree.computeRootTreeHash() = %v", err)
	} else if !bytes.Equal(treeHash, []byte(tc.TreeHashBefore)) {
		t.Errorf("ratchetTree.computeRootTreeHash() = %v, want %v", treeHash, tc.TreeHashBefore)
	}

	var prop Proposal
	if err := Unmarshal([]byte(tc.Proposal), &prop); err != nil {
		t.Fatalf("unmarshal(proposal) = %v", err)
	}

	switch prop.proposalType {
	case ProposalTypeAdd:
		ctx := GroupContext{
			Version:     prop.add.keyPackage.Version,
			CipherSuite: prop.add.keyPackage.CipherSuite,
		}
		if err := prop.add.keyPackage.Verify(&ctx); err != nil {
			t.Errorf("keyPackage.verify() = %v", err)
		}
		tree.Add(&prop.add.keyPackage.LeafNode)
	case ProposalTypeUpdate:
		signatureKeys, encryptionKeys := tree.Keys()
		err := prop.update.leafNode.Verify(&LeafNodeVerifyOptions{
			cipherSuite:    tc.CipherSuite,
			groupID:        nil,
			leafIndex:      tc.ProposalSender,
			supportedCreds: tree.SupportedCreds(),
			signatureKeys:  signatureKeys,
			encryptionKeys: encryptionKeys,
			now:            func() time.Time { return time.Time{} },
		})
		if err != nil {
			t.Errorf("leafNode.verify() = %v", err)
		}
		tree.Update(tc.ProposalSender, &prop.update.leafNode)
	case ProposalTypeRemove:
		if tree.GetLeaf(prop.remove.removed) == nil {
			t.Errorf("leaf node %v is blank", prop.remove.removed)
		}
		tree.Remove(prop.remove.removed)
	default:
		panic("unreachable")
	}

	rawTree, err := Marshal(&tree)
	if err != nil {
		t.Fatalf("marshal(tree) = %v", err)
	} else if !bytes.Equal(rawTree, []byte(tc.TreeAfter)) {
		t.Errorf("marshal(tree) = %v, want %v", rawTree, tc.TreeAfter)
	}

	treeHash, err = tree.ComputeRootTreeHash(tc.CipherSuite)
	if err != nil {
		t.Errorf("ratchetTree.computeRootTreeHash() = %v", err)
	} else if !bytes.Equal(treeHash, []byte(tc.TreeHashAfter)) {
		t.Errorf("ratchetTree.computeRootTreeHash() = %v, want %v", treeHash, tc.TreeHashAfter)
	}
}

func TestTreeOperations(t *testing.T) {
	var tests []treeOperationsTest
	loadTestVector(t, "testdata/tree-operations.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testTreeOperations(t, &tc)
		})
	}
}
