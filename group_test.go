package mls

import (
	"bytes"
	"fmt"
	"testing"
)

type welcomeTest struct {
	CipherSuite CipherSuite `json:"cipher_suite"`

	InitPriv  testBytes `json:"init_priv"`
	SignerPub testBytes `json:"signer_pub"`

	KeyPackage testBytes `json:"key_package"`
	Welcome    testBytes `json:"welcome"`
}

func testWelcome(t *testing.T, tc *welcomeTest) {
	var welcomeMsg MLSMessage
	if err := welcomeMsg.Unmarshal(tc.Welcome.ByteString()); err != nil {
		t.Fatalf("unmarshal(welcome) = %v", err)
	} else if welcomeMsg.WireFormat != WireFormatMLSWelcome {
		t.Fatalf("wireFormat = %v, want %v", welcomeMsg.WireFormat, WireFormatMLSWelcome)
	}
	welcome := welcomeMsg.Welcome

	var keyPackageMsg MLSMessage
	if err := keyPackageMsg.Unmarshal(tc.KeyPackage.ByteString()); err != nil {
		t.Fatalf("unmarshal(keyPackage) = %v", err)
	} else if keyPackageMsg.WireFormat != WireFormatMLSKeyPackage {
		t.Fatalf("wireFormat = %v, want %v", keyPackageMsg.WireFormat, WireFormatMLSKeyPackage)
	}
	keyPackage := keyPackageMsg.KeyPackage

	keyPackageRef, err := keyPackage.GenerateRef()
	if err != nil {
		t.Fatalf("keyPackage.generateRef() = %v", err)
	}

	groupSecrets, err := welcome.DecryptGroupSecrets(keyPackageRef, []byte(tc.InitPriv))
	if err != nil {
		t.Fatalf("welcome.decryptGroupSecrets() = %v", err)
	}

	groupInfo, err := welcome.DecryptGroupInfo(groupSecrets.JoinerSecret, nil)
	if err != nil {
		t.Fatalf("welcome.decryptGroupInfo() = %v", err)
	}
	if !groupInfo.VerifySignature(SignaturePublicKey(tc.SignerPub)) {
		t.Errorf("groupInfo.verifySignature() failed")
	}
	if !groupInfo.VerifyConfirmationTag(groupSecrets.JoinerSecret, nil) {
		t.Errorf("groupInfo.verifyConfirmationTag() failed")
	}
}

func TestWelcome(t *testing.T) {
	var tests []welcomeTest
	loadTestVector(t, "testdata/welcome.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testWelcome(t, &tc)
		})
	}
}

type messageProtectionTest struct {
	CipherSuite CipherSuite `json:"cipher_suite"`

	GroupID                 testBytes `json:"group_id"`
	Epoch                   uint64    `json:"epoch"`
	TreeHash                testBytes `json:"tree_hash"`
	ConfirmedTranscriptHash testBytes `json:"confirmed_transcript_hash"`

	SignaturePriv testBytes `json:"signature_priv"`
	SignaturePub  testBytes `json:"signature_pub"`

	EncryptionSecret testBytes `json:"encryption_secret"`
	SenderDataSecret testBytes `json:"sender_data_secret"`
	MembershipKey    testBytes `json:"membership_key"`

	Proposal     testBytes `json:"proposal"`
	ProposalPub  testBytes `json:"proposal_pub"`
	ProposalPriv testBytes `json:"proposal_priv"`

	Commit     testBytes `json:"commit"`
	CommitPub  testBytes `json:"commit_pub"`
	CommitPriv testBytes `json:"commit_priv"`

	Application     testBytes `json:"application"`
	ApplicationPriv testBytes `json:"application_priv"`
}

func testMessageProtectionPub(t *testing.T, tc *messageProtectionTest, ctx *GroupContext, wantRaw, rawPub []byte) {
	var msg MLSMessage
	if err := Unmarshal(rawPub, &msg); err != nil {
		t.Fatalf("unmarshal() = %v", err)
	} else if msg.WireFormat != WireFormatMLSPublicMessage {
		t.Fatalf("unmarshal(): wireFormat = %v, want %v", msg.WireFormat, WireFormatMLSPublicMessage)
	}
	pubMsg := msg.PublicMessage

	verifyPublicMessage(t, tc, ctx, pubMsg, wantRaw)

	pubMsg, err := SignPublicMessage(tc.CipherSuite, []byte(tc.SignaturePriv), &pubMsg.Content, ctx)
	if err != nil {
		t.Errorf("signPublicMessage() = %v", err)
	}
	if err := pubMsg.SignMembershipTag(tc.CipherSuite, []byte(tc.MembershipKey), ctx); err != nil {
		t.Errorf("signMembershipTag() = %v", err)
	}
	verifyPublicMessage(t, tc, ctx, pubMsg, wantRaw)
}

func verifyPublicMessage(t *testing.T, tc *messageProtectionTest, ctx *GroupContext, pubMsg *PublicMessage, wantRaw []byte) {
	authContent := pubMsg.AuthenticatedContent()
	if !authContent.VerifySignature(tc.CipherSuite, []byte(tc.SignaturePub), ctx) {
		t.Errorf("verifySignature() failed")
	}
	if !pubMsg.VerifyMembershipTag(tc.CipherSuite, []byte(tc.MembershipKey), ctx) {
		t.Errorf("verifyMembershipTag() failed")
	}

	var (
		raw []byte
		err error
	)
	switch pubMsg.Content.ContentType {
	case contentTypeApplication:
		raw = pubMsg.Content.ApplicationData
	case contentTypeProposal:
		raw, err = Marshal(pubMsg.Content.Proposal)
	case contentTypeCommit:
		raw, err = Marshal(pubMsg.Content.Commit)
	default:
		t.Errorf("unexpected content type %v", pubMsg.Content.ContentType)
	}
	if err != nil {
		t.Errorf("marshal() = %v", err)
	} else if !bytes.Equal(raw, wantRaw) {
		t.Errorf("marshal() = %v, want %v", raw, wantRaw)
	}
}

func testMessageProtectionPriv(t *testing.T, tc *messageProtectionTest, ctx *GroupContext, wantRaw, rawPriv []byte) {
	var msg MLSMessage
	if err := Unmarshal(rawPriv, &msg); err != nil {
		t.Fatalf("unmarshal() = %v", err)
	} else if msg.WireFormat != WireFormatMLSPrivateMessage {
		t.Fatalf("unmarshal(): wireFormat = %v, want %v", msg.WireFormat, WireFormatMLSPrivateMessage)
	}
	privMsg := msg.PrivateMessage

	tree, err := DeriveSecretTree(tc.CipherSuite, NumLeaves(2), []byte(tc.EncryptionSecret))
	if err != nil {
		t.Fatalf("deriveSecretTree() = %v", err)
	}

	label := RatchetLabelFromContentType(privMsg.ContentType)
	li := LeafIndex(1)
	secret, err := tree.DeriveRatchetRoot(tc.CipherSuite, li.NodeIndex(), label)
	if err != nil {
		t.Fatalf("deriveRatchetRoot() = %v", err)
	}

	content := decryptPrivateMessage(t, tc, ctx, secret, privMsg, wantRaw)

	senderData, err := NewSenderData(li, 0) // TODO: set generation > 0
	if err != nil {
		t.Fatalf("newSenderData() = %v", err)
	}
	framedContent := FramedContent{
		GroupID: GroupID(tc.GroupID),
		Epoch:   tc.Epoch,
		Sender: Sender{
			SenderType: senderTypeMember,
			LeafIndex:  li,
		},
		ContentType:     privMsg.ContentType,
		ApplicationData: content.ApplicationData,
		Proposal:        content.Proposal,
		Commit:          content.Commit,
	}
	privMsg, err = EncryptPrivateMessage(tc.CipherSuite, []byte(tc.SignaturePriv), secret, []byte(tc.SenderDataSecret), &framedContent, senderData, ctx)
	if err != nil {
		t.Fatalf("encryptPrivateMessage() = %v", err)
	}
	decryptPrivateMessage(t, tc, ctx, secret, privMsg, wantRaw)
}

func decryptPrivateMessage(t *testing.T, tc *messageProtectionTest, ctx *GroupContext, secret RatchetSecret, privMsg *PrivateMessage, wantRaw []byte) *PrivateMessageContent {
	senderData, err := privMsg.DecryptSenderData(tc.CipherSuite, []byte(tc.SenderDataSecret))
	if err != nil {
		t.Fatalf("decryptSenderData() = %v", err)
	}

	for secret.Generation != senderData.Generation {
		secret, err = secret.DeriveNext(tc.CipherSuite)
		if err != nil {
			t.Fatalf("deriveNext() = %v", err)
		}
	}

	content, err := privMsg.DecryptContent(tc.CipherSuite, secret, senderData.ReuseGuard)
	if err != nil {
		t.Fatalf("decryptContent() = %v", err)
	}

	authContent := privMsg.AuthenticatedContent(senderData, content)
	if !authContent.VerifySignature(tc.CipherSuite, []byte(tc.SignaturePub), ctx) {
		t.Errorf("verifySignature() failed")
	}

	var raw []byte
	switch privMsg.ContentType {
	case contentTypeApplication:
		raw = content.ApplicationData
	case contentTypeProposal:
		raw, err = Marshal(content.Proposal)
	case contentTypeCommit:
		raw, err = Marshal(content.Commit)
	default:
		t.Errorf("unexpected content type %v", privMsg.ContentType)
	}
	if err != nil {
		t.Errorf("marshal() = %v", err)
	} else if !bytes.Equal(raw, wantRaw) {
		t.Errorf("marshal() = %v, want %v", raw, wantRaw)
	}

	return content
}

func testMessageProtection(t *testing.T, tc *messageProtectionTest) {
	ctx := GroupContext{
		Version:                 ProtocolVersionMLS10,
		CipherSuite:             tc.CipherSuite,
		GroupID:                 GroupID(tc.GroupID),
		Epoch:                   tc.Epoch,
		TreeHash:                []byte(tc.TreeHash),
		ConfirmedTranscriptHash: []byte(tc.ConfirmedTranscriptHash),
	}

	wireFormats := []struct {
		name           string
		raw, pub, priv testBytes
	}{
		{"proposal", tc.Proposal, tc.ProposalPub, tc.ProposalPriv},
		{"commit", tc.Commit, tc.CommitPub, tc.CommitPriv},
		{"application", tc.Application, nil, tc.ApplicationPriv},
	}
	for _, wireFormat := range wireFormats {
		t.Run(wireFormat.name, func(t *testing.T) {
			raw := []byte(wireFormat.raw)
			pub := []byte(wireFormat.pub)
			priv := []byte(wireFormat.priv)
			if wireFormat.pub != nil {
				t.Run("pub", func(t *testing.T) {
					testMessageProtectionPub(t, tc, &ctx, raw, pub)
				})
			}
			t.Run("priv", func(t *testing.T) {
				testMessageProtectionPriv(t, tc, &ctx, raw, priv)
			})
		})
	}
}

func TestMessageProtection(t *testing.T) {
	var tests []messageProtectionTest
	loadTestVector(t, "testdata/message-protection.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testMessageProtection(t, &tc)
		})
	}
}
