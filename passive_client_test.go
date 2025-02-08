package mls

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
)

type passiveClientTest struct {
	CipherSuite CipherSuite `json:"cipher_suite"`

	ExternalPSKs []struct {
		PSKID testBytes `json:"psk_id"`
		PSK   testBytes `json:"psk"`
	} `json:"external_psks"`
	KeyPackage     testBytes `json:"key_package"`
	SignaturePriv  testBytes `json:"signature_priv"`
	EncryptionPriv testBytes `json:"encryption_priv"`
	InitPriv       testBytes `json:"init_priv"`

	Welcome                   testBytes `json:"welcome"`
	RatchetTree               testBytes `json:"ratchet_tree"`
	InitialEpochAuthenticator testBytes `json:"initial_epoch_authenticator"`

	Epochs []struct {
		Proposals          []testBytes `json:"proposals"`
		Commit             testBytes   `json:"commit"`
		EpochAuthenticator testBytes   `json:"epoch_authenticator"`
	} `json:"epochs"`
}

type pendingProposal struct {
	ref      ProposalRef
	proposal *Proposal
	sender   LeafIndex
}

func testPassiveClient(t *testing.T, tc *passiveClientTest) {
	cs := tc.CipherSuite
	initPriv := normalizePriv(cs, []byte(tc.InitPriv))
	encryptionPriv := normalizePriv(cs, []byte(tc.EncryptionPriv))
	signaturePriv := normalizePriv(cs, []byte(tc.SignaturePriv))

	// TODO: drop the seed size check, see:
	// https://github.com/cloudflare/circl/issues/486
	kem, kdf, _ := cs.HPKE().Params()
	if kem.Scheme().SeedSize() != kdf.ExtractSize() {
		t.Skip("TODO: kem.Scheme().SeedSize() != kdf.ExtractSize()")
	}

	msg, err := unmarshalMLSMessage(tc.Welcome, WireFormatMLSWelcome)
	if err != nil {
		t.Fatalf("unmarshal(welcome) = %v", err)
	}
	welcome := msg.Welcome
	if welcome.CipherSuite != cs {
		t.Fatalf("welcome.cipherSuite = %v, want %v", welcome.CipherSuite, cs)
	}

	msg, err = unmarshalMLSMessage(tc.KeyPackage, WireFormatMLSKeyPackage)
	if err != nil {
		t.Fatalf("unmarshal(keyPackage) = %v", err)
	}
	keyPkg := msg.KeyPackage
	if keyPkg.CipherSuite != welcome.CipherSuite {
		t.Fatalf("keyPkg.cipherSuite = %v, want %v", keyPkg.CipherSuite, welcome.CipherSuite)
	}

	if err := checkEncryptionKeyPair(cs, keyPkg.InitKey, initPriv); err != nil {
		t.Errorf("invalid init keypair: %v", err)
	}
	if err := checkEncryptionKeyPair(cs, keyPkg.LeafNode.EncryptionKey, encryptionPriv); err != nil {
		t.Errorf("invalid encryption keypair: %v", err)
	}
	if err := checkSignatureKeyPair(cs, []byte(keyPkg.LeafNode.SignatureKey), signaturePriv); err != nil {
		t.Errorf("invalid signature keypair: %v", err)
	}

	keyPkgRef, err := keyPkg.GenerateRef()
	if err != nil {
		t.Fatalf("keyPackage.generateRef() = %v", err)
	}

	groupSecrets, err := welcome.DecryptGroupSecrets(keyPkgRef, initPriv)
	if err != nil {
		t.Fatalf("welcome.decryptGroupSecrets() = %v", err)
	}

	if !groupSecrets.VerifySingleReinitOrBranchPSK() {
		t.Errorf("groupSecrets.verifySingleReinitOrBranchPSK() failed")
	}

	var psks [][]byte
	for _, pskID := range groupSecrets.PSKs {
		if pskID.PSKType != PSKTypeExternal {
			t.Fatalf("group secrets contain a non-external PSK ID")
		}

		found := false
		for _, epsk := range tc.ExternalPSKs {
			if bytes.Equal([]byte(epsk.PSKID), pskID.PSKID) {
				psks = append(psks, []byte(epsk.PSK))
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("PSK ID %v not found", pskID.PSKID)
		}
	}

	pskSecret, err := ExtractPSKSecret(cs, groupSecrets.PSKs, psks)
	if err != nil {
		t.Fatalf("extractPSKSecret() = %v", err)
	}

	groupInfo, err := welcome.DecryptGroupInfo(groupSecrets.JoinerSecret, pskSecret)
	if err != nil {
		t.Fatalf("welcome.decryptGroupInfo() = %v", err)
	}

	rawTree := []byte(tc.RatchetTree)
	if rawTree == nil {
		rawTree = FindExtensionData(groupInfo.Extensions, ExtensionTypeRatchetTree)
	}
	if rawTree == nil {
		t.Fatalf("missing ratchet tree")
	}

	var tree RatchetTree
	if err := Unmarshal(rawTree, &tree); err != nil {
		t.Fatalf("unmarshal(ratchetTree) = %v", err)
	}

	signerNode := tree.GetLeaf(groupInfo.Signer)
	if signerNode == nil {
		t.Errorf("signer node is blank")
	} else if !groupInfo.VerifySignature(signerNode.SignatureKey) {
		t.Errorf("groupInfo.verifySignature() failed")
	}
	if !groupInfo.VerifyConfirmationTag(groupSecrets.JoinerSecret, pskSecret) {
		t.Errorf("groupInfo.verifyConfirmationTag() failed")
	}
	if groupInfo.GroupContext.CipherSuite != keyPkg.CipherSuite {
		t.Errorf("groupInfo.cipherSuite = %v, want %v", groupInfo.GroupContext.CipherSuite, keyPkg.CipherSuite)
	}

	disableLifetimeCheck := func() time.Time { return time.Time{} }
	if err := tree.VerifyIntegrity(&groupInfo.GroupContext, disableLifetimeCheck); err != nil {
		t.Errorf("tree.verifyIntegrity() = %v", err)
	}

	myLeafIndex, ok := tree.FindLeaf(&keyPkg.LeafNode)
	if !ok {
		t.Errorf("tree.findLeaf() = false")
	}

	privTree := make([][]byte, len(tree))
	privTree[int(myLeafIndex.NodeIndex())] = encryptionPriv

	if groupSecrets.PathSecret != nil {
		nodeIndex := CommonAncestor(myLeafIndex.NodeIndex(), groupInfo.Signer.NodeIndex())
		nodePriv, err := NodePrivFromPathSecret(cs, groupSecrets.PathSecret, tree.Get(nodeIndex).EncryptionKey())
		if err != nil {
			t.Fatalf("failed to derive node %v private key from path secret: %v", nodeIndex, err)
		}
		privTree[int(nodeIndex)] = nodePriv

		pathSecret := groupSecrets.PathSecret
		for {
			nodeIndex, ok = tree.numLeaves().Parent(nodeIndex)
			if !ok {
				break
			}

			pathSecret, err := cs.DeriveSecret(pathSecret, []byte("path"))
			if err != nil {
				t.Fatalf("deriveSecret(pathSecret[n-1]) = %v", err)
			}

			nodePriv, err := NodePrivFromPathSecret(cs, pathSecret, tree.Get(nodeIndex).EncryptionKey())
			if err != nil {
				t.Fatalf("failed to derive node %v private key from path secret: %v", nodeIndex, err)
			}
			privTree[int(nodeIndex)] = nodePriv
		}
	}

	// TODO: perform other group info verification steps

	groupCtx := groupInfo.GroupContext

	epochSecret, err := groupCtx.ExtractEpochSecret(groupSecrets.JoinerSecret, pskSecret)
	if err != nil {
		t.Fatalf("groupContext.extractEpochSecret() = %v", err)
	}
	epochAuthenticator, err := cs.DeriveSecret(epochSecret, SecretLabelAuthentication)
	if err != nil {
		t.Errorf("deriveSecret(authentication) = %v", err)
	} else if !bytes.Equal(epochAuthenticator, []byte(tc.InitialEpochAuthenticator)) {
		t.Errorf("deriveSecret(authentication) = %v, want %v", epochAuthenticator, tc.InitialEpochAuthenticator)
	}

	initSecret, err := cs.DeriveSecret(epochSecret, SecretLabelInit)
	if err != nil {
		t.Errorf("deriveSecret(init) = %v", err)
	}

	interimTranscriptHash, err := NextInterimTranscriptHash(cs, groupCtx.ConfirmedTranscriptHash, groupInfo.ConfirmationTag)
	if err != nil {
		t.Errorf("nextInterimTranscriptHash() = %v", err)
	}

	for i, epoch := range tc.Epochs {
		t.Logf("epoch %v", i)

		var pendingProposals []pendingProposal
		for _, rawProposal := range epoch.Proposals {
			var msg MLSMessage
			if err := Unmarshal([]byte(rawProposal), &msg); err != nil {
				t.Fatalf("unmarshal(proposal) = %v", err)
			} else if msg.WireFormat != WireFormatMLSPublicMessage {
				t.Fatalf("TODO: wireFormat = %v", msg.WireFormat)
			}
			pubMsg := msg.PublicMessage

			// TODO: public message checks

			authContent := pubMsg.AuthenticatedContent()

			if authContent.Content.ContentType != contentTypeProposal {
				t.Errorf("contentType = %v, want %v", authContent.Content.ContentType, contentTypeProposal)
			}
			proposal := authContent.Content.Proposal

			ref, err := authContent.GenerateProposalRef(cs)
			if err != nil {
				t.Fatalf("proposal.generateRef() = %v", err)
			}

			pendingProposals = append(pendingProposals, pendingProposal{
				ref:      ref,
				proposal: proposal,
				sender:   pubMsg.Content.Sender.LeafIndex,
			})
		}

		var msg MLSMessage
		if err := Unmarshal([]byte(epoch.Commit), &msg); err != nil {
			t.Fatalf("unmarshal(commit) = %v", err)
		} else if msg.WireFormat != WireFormatMLSPublicMessage {
			t.Fatalf("TODO: wireFormat = %v", msg.WireFormat)
		}
		pubMsg := msg.PublicMessage

		if pubMsg.Content.Epoch != groupCtx.Epoch {
			t.Errorf("epoch = %v, want %v", pubMsg.Content.Epoch, groupCtx.Epoch)
		}

		if pubMsg.Content.Sender.SenderType != senderTypeMember {
			t.Fatalf("TODO: senderType = %v", pubMsg.Content.Sender.SenderType)
		}
		senderLeafIndex := pubMsg.Content.Sender.LeafIndex
		// TODO: check tree length
		senderNode := tree.GetLeaf(senderLeafIndex)
		if senderNode == nil {
			t.Fatalf("blank leaf node for sender")
		}

		authContent := pubMsg.AuthenticatedContent()
		if !authContent.VerifySignature(cs, []byte(senderNode.SignatureKey), &groupCtx) {
			t.Errorf("verifySignature() failed")
		}

		membershipKey, err := cs.DeriveSecret(epochSecret, SecretLabelMembership)
		if err != nil {
			t.Errorf("deriveSecret(membership) = %v", err)
		} else if !pubMsg.VerifyMembershipTag(cs, membershipKey, &groupCtx) {
			t.Errorf("publicMessage.verifyMembershipTag() failed")
		}

		if authContent.Content.ContentType != contentTypeCommit {
			t.Errorf("contentType = %v, want %v", authContent.Content.ContentType, contentTypeCommit)
		}
		commit := authContent.Content.Commit

		var (
			proposals []Proposal
			senders   []LeafIndex
		)
		for _, propOrRef := range commit.Proposals {
			switch propOrRef.Type {
			case ProposalOrRefTypeProposal:
				proposals = append(proposals, *propOrRef.Proposal)
				senders = append(senders, senderLeafIndex)
			case ProposalOrRefTypeReference:
				var found bool
				for _, pp := range pendingProposals {
					if pp.ref.Equal(propOrRef.Reference) {
						found = true
						proposals = append(proposals, *pp.proposal)
						senders = append(senders, pp.sender)
						break
					}
				}
				if !found {
					t.Fatalf("cannot find proposal reference %v", propOrRef.Reference)
				}
			}
		}

		if err := VerifyProposalList(proposals, senders, senderLeafIndex); err != nil {
			t.Errorf("verifyProposals() = %v", err)
		}
		// TODO: additional proposal list checks

		newTree := make(RatchetTree, len(tree))
		copy(newTree, tree)
		newTree.Apply(proposals, senders)

		newPrivTree := make([][]byte, len(newTree))
		for i := range tree {
			if i < len(newPrivTree) {
				newPrivTree[i] = privTree[i]
			}
		}

		if ProposalListNeedsPath(proposals) && commit.Path == nil {
			t.Errorf("proposal list needs update path")
		}

		var (
			pskIDs []PreSharedKeyID
			psks   [][]byte
		)
		for _, prop := range proposals {
			if prop.ProposalType != ProposalTypePSK {
				continue
			}

			pskID := prop.PreSharedKey.PSK
			if pskID.PSKType != PSKTypeExternal {
				t.Skipf("TODO: PSK ID type = %v", pskID.PSKType)
			}

			found := false
			for _, epsk := range tc.ExternalPSKs {
				if bytes.Equal([]byte(epsk.PSKID), pskID.PSKID) {
					pskIDs = append(pskIDs, pskID)
					psks = append(psks, []byte(epsk.PSK))
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("PSK ID %v not found", pskID.PSKID)
			}
		}

		newGroupCtx := groupCtx
		newGroupCtx.Epoch++

		_, kdf, _ := cs.HPKE().Params()
		commitSecret := make([]byte, kdf.ExtractSize())
		if commit.Path != nil {
			if commit.Path.LeafNode.LeafNodeSource != LeafNodeSourceCommit {
				t.Errorf("commit path leaf node source must be commit")
			}

			// The same signature key can be re-used, but the encryption key
			// must change
			signatureKeys, encryptionKeys := newTree.Keys()
			delete(signatureKeys, string(senderNode.SignatureKey))
			err := commit.Path.LeafNode.Verify(&LeafNodeVerifyOptions{
				CipherSuite:    cs,
				GroupID:        groupCtx.GroupID,
				LeafIndex:      senderLeafIndex,
				SupportedCreds: newTree.SupportedCreds(),
				SignatureKeys:  signatureKeys,
				EncryptionKeys: encryptionKeys,
				Now:            func() time.Time { return time.Time{} },
			})
			if err != nil {
				t.Errorf("leafNode.verify() = %v", err)
			}

			for _, updateNode := range commit.Path.Nodes {
				if _, dup := encryptionKeys[string(updateNode.EncryptionKey)]; dup {
					t.Errorf("encryption key in update path already used in ratchet tree")
					break
				}
			}

			if err := newTree.MergeUpdatePath(cs, senderLeafIndex, commit.Path); err != nil {
				t.Errorf("ratchetTree.mergeUpdatePath() = %v", err)
			}

			newGroupCtx.TreeHash, err = newTree.ComputeRootTreeHash(cs)
			if err != nil {
				t.Fatalf("ratchetTree.computeRootTreeHash() = %v", err)
			}

			// TODO: update group context extensions

			commitSecret, err = newTree.DecryptPathSecrets(cs, &newGroupCtx, senderLeafIndex, myLeafIndex, commit.Path, newPrivTree)
			if err != nil {
				t.Fatalf("ratchetTree.decryptPathSecrets() = %v", err)
			}
		}

		newGroupCtx.ConfirmedTranscriptHash, err = authContent.ConfirmedTranscriptHashInput().hash(cs, interimTranscriptHash)
		if err != nil {
			t.Fatalf("confirmedTranscriptHashInput.hash() = %v", err)
		}

		newInterimTranscriptHash, err := NextInterimTranscriptHash(cs, newGroupCtx.ConfirmedTranscriptHash, authContent.Auth.ConfirmationTag)
		if err != nil {
			t.Fatalf("nextInterimTranscriptHash() = %v", err)
		}

		newPSKSecret, err := ExtractPSKSecret(cs, pskIDs, psks)
		if err != nil {
			t.Fatalf("extractPSKSecret() = %v", err)
		}

		newJoinerSecret, err := newGroupCtx.ExtractJoinerSecret(initSecret, commitSecret)
		if err != nil {
			t.Fatalf("groupContext.extractJoinerSecret() = %v", err)
		}

		newEpochSecret, err := newGroupCtx.ExtractEpochSecret(newJoinerSecret, newPSKSecret)
		if err != nil {
			t.Fatalf("groupContext.extractEpochSecret() = %v", err)
		}
		epochAuthenticator, err := cs.DeriveSecret(newEpochSecret, SecretLabelAuthentication)
		if err != nil {
			t.Fatalf("deriveSecret(authentication) = %v", err)
		} else if !bytes.Equal(epochAuthenticator, []byte(epoch.EpochAuthenticator)) {
			t.Errorf("deriveSecret(authentication) = %v, want %v", epochAuthenticator, epoch.EpochAuthenticator)
		}

		newInitSecret, err := cs.DeriveSecret(newEpochSecret, SecretLabelInit)
		if err != nil {
			t.Fatalf("deriveSecret(init) = %v", err)
		}

		confirmationKey, err := cs.DeriveSecret(newEpochSecret, SecretLabelConfirm)
		if err != nil {
			t.Fatalf("deriveSecret(confirm) = %v", err)
		}
		confirmationTag := cs.SignMAC(confirmationKey, newGroupCtx.ConfirmedTranscriptHash)
		if !bytes.Equal(confirmationTag, authContent.Auth.ConfirmationTag) {
			t.Errorf("invalid confirmation tag: got %v, want %v", confirmationTag, authContent.Auth.ConfirmationTag)
		}

		tree = newTree
		privTree = newPrivTree
		groupCtx = newGroupCtx
		interimTranscriptHash = newInterimTranscriptHash
		pskSecret = newPSKSecret
		epochSecret = newEpochSecret
		initSecret = newInitSecret
	}
}

// normalizePriv ensures that private keys in test vectors have the correct
// size according to the HPKE specification. See:
// https://github.com/mlswg/mls-implementations/issues/176
func normalizePriv(cs CipherSuite, priv []byte) []byte {
	kem, _, _ := cs.HPKE().Params()
	privSize := kem.Scheme().PrivateKeySize()
	if kem != hpke.KEM_P521_HKDF_SHA512 || len(priv) >= privSize {
		return priv
	}
	b := make([]byte, privSize)
	copy(b[privSize-len(priv):], priv)
	return b
}

func unmarshalMLSMessage(raw testBytes, wf WireFormat) (*MLSMessage, error) {
	var msg MLSMessage
	if err := Unmarshal([]byte(raw), &msg); err != nil {
		return nil, err
	} else if msg.WireFormat != wf {
		return nil, fmt.Errorf("invalid wireFormat: got %v, want %v", msg.WireFormat, wf)
	}
	return &msg, nil
}

func checkEncryptionKeyPair(cs CipherSuite, pub, priv []byte) error {
	wantPlaintext := []byte("foo")
	label := []byte("bar")

	kemOutput, ciphertext, err := cs.EncryptWithLabel(pub, label, nil, wantPlaintext)
	if err != nil {
		return err
	}

	plaintext, err := cs.DecryptWithLabel(priv, label, nil, kemOutput, ciphertext)
	if err != nil {
		return err
	}

	if !bytes.Equal(plaintext, wantPlaintext) {
		return fmt.Errorf("got plaintext %v, want %v", plaintext, wantPlaintext)
	}

	return nil
}

func checkSignatureKeyPair(cs CipherSuite, pub, priv []byte) error {
	content := []byte("foo")
	label := []byte("bar")

	signature, err := cs.SignWithLabel(priv, label, content)
	if err != nil {
		return err
	}

	if !cs.VerifyWithLabel(pub, label, content, signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func TestPassiveClientWelcome(t *testing.T) {
	var tests []passiveClientTest
	loadTestVector(t, "testdata/passive-client-welcome.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testPassiveClient(t, &tc)
		})
	}
}

func TestPassiveClientCommit(t *testing.T) {
	var tests []passiveClientTest
	loadTestVector(t, "testdata/passive-client-handling-commit.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testPassiveClient(t, &tc)
		})
	}
}

func TestPassiveClientRandom(t *testing.T) {
	var tests []passiveClientTest
	loadTestVector(t, "testdata/passive-client-random.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			t.Skip("TODO") // "mls: invalid UpdatePathNode.encrypted_path_secret length"
			testPassiveClient(t, &tc)
		})
	}
}
