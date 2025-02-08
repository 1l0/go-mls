package mls

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

type ProtocolVersion uint16

const (
	ProtocolVersionMLS10 ProtocolVersion = 1
)

type contentType uint8

const (
	contentTypeApplication contentType = 1
	contentTypeProposal    contentType = 2
	contentTypeCommit      contentType = 3
)

func (ct *contentType) unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint8((*uint8)(ct)) {
		return io.ErrUnexpectedEOF
	}
	switch *ct {
	case contentTypeApplication, contentTypeProposal, contentTypeCommit:
		return nil
	default:
		return fmt.Errorf("mls: invalid content type %d", *ct)
	}
}

func (ct contentType) marshal(b *cryptobyte.Builder) {
	b.AddUint8(uint8(ct))
}

type senderType uint8

const (
	senderTypeMember            senderType = 1
	senderTypeExternal          senderType = 2
	senderTypeNewMemberProposal senderType = 3
	senderTypeNewMemberCommit   senderType = 4
)

func (st *senderType) unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint8((*uint8)(st)) {
		return io.ErrUnexpectedEOF
	}
	switch *st {
	case senderTypeMember, senderTypeExternal, senderTypeNewMemberProposal, senderTypeNewMemberCommit:
		return nil
	default:
		return fmt.Errorf("mls: invalid sender type %d", *st)
	}
}

func (st senderType) marshal(b *cryptobyte.Builder) {
	b.AddUint8(uint8(st))
}

type Sender struct {
	SenderType  senderType
	LeafIndex   LeafIndex // for senderTypeMember
	SenderIndex uint32    // for senderTypeExternal
}

func (snd *Sender) Unmarshal(s *cryptobyte.String) error {
	*snd = Sender{}
	if err := snd.SenderType.unmarshal(s); err != nil {
		return err
	}
	switch snd.SenderType {
	case senderTypeMember:
		if !s.ReadUint32((*uint32)(&snd.LeafIndex)) {
			return io.ErrUnexpectedEOF
		}
	case senderTypeExternal:
		if !s.ReadUint32(&snd.SenderIndex) {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func (snd *Sender) Marshal(b *cryptobyte.Builder) {
	snd.SenderType.marshal(b)
	switch snd.SenderType {
	case senderTypeMember:
		b.AddUint32(uint32(snd.LeafIndex))
	case senderTypeExternal:
		b.AddUint32(snd.SenderIndex)
	}
}

type WireFormat uint16

// http://www.iana.org/assignments/mls/mls.xhtml#mls-wire-formats
const (
	WireFormatMLSPublicMessage  WireFormat = 0x0001
	WireFormatMLSPrivateMessage WireFormat = 0x0002
	WireFormatMLSWelcome        WireFormat = 0x0003
	WireFormatMLSGroupInfo      WireFormat = 0x0004
	WireFormatMLSKeyPackage     WireFormat = 0x0005
)

func (wf *WireFormat) Unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint16((*uint16)(wf)) {
		return io.ErrUnexpectedEOF
	}
	switch *wf {
	case WireFormatMLSPublicMessage, WireFormatMLSPrivateMessage, WireFormatMLSWelcome, WireFormatMLSGroupInfo, WireFormatMLSKeyPackage:
		return nil
	default:
		return fmt.Errorf("mls: invalid wire format %d", *wf)
	}
}

func (wf WireFormat) Marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(wf))
}

// GroupID is an application-specific group identifier.
type GroupID []byte

type FramedContent struct {
	GroupID           GroupID
	Epoch             uint64
	Sender            Sender
	AuthenticatedData []byte

	ContentType     contentType
	ApplicationData []byte    // for contentTypeApplication
	Proposal        *Proposal // for contentTypeProposal
	Commit          *Commit   // for contentTypeCommit
}

func (content *FramedContent) Unmarshal(s *cryptobyte.String) error {
	*content = FramedContent{}

	if !ReadOpaqueVec(s, (*[]byte)(&content.GroupID)) || !s.ReadUint64(&content.Epoch) {
		return io.ErrUnexpectedEOF
	}
	if err := content.Sender.Unmarshal(s); err != nil {
		return err
	}
	if !ReadOpaqueVec(s, &content.AuthenticatedData) {
		return io.ErrUnexpectedEOF
	}
	if err := content.ContentType.unmarshal(s); err != nil {
		return err
	}

	switch content.ContentType {
	case contentTypeApplication:
		if !ReadOpaqueVec(s, &content.ApplicationData) {
			return io.ErrUnexpectedEOF
		}
		return nil
	case contentTypeProposal:
		content.Proposal = new(Proposal)
		return content.Proposal.Unmarshal(s)
	case contentTypeCommit:
		content.Commit = new(Commit)
		return content.Commit.Unmarshal(s)
	default:
		panic("unreachable")
	}
}

func (content *FramedContent) marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, []byte(content.GroupID))
	b.AddUint64(content.Epoch)
	content.Sender.Marshal(b)
	WriteOpaqueVec(b, content.AuthenticatedData)
	content.ContentType.marshal(b)
	switch content.ContentType {
	case contentTypeApplication:
		WriteOpaqueVec(b, content.ApplicationData)
	case contentTypeProposal:
		content.Proposal.Marshal(b)
	case contentTypeCommit:
		content.Commit.Marshal(b)
	default:
		panic("unreachable")
	}
}

type MLSMessage struct {
	Version        ProtocolVersion
	WireFormat     WireFormat
	PublicMessage  *PublicMessage  // for wireFormatMLSPublicMessage
	PrivateMessage *PrivateMessage // for wireFormatMLSPrivateMessage
	Welcome        *Welcome        // for wireFormatMLSWelcome
	GroupInfo      *GroupInfo      // for wireFormatMLSGroupInfo
	KeyPackage     *KeyPackage     // for wireFormatMLSKeyPackage
}

func (msg *MLSMessage) Unmarshal(s *cryptobyte.String) error {
	*msg = MLSMessage{}

	if !s.ReadUint16((*uint16)(&msg.Version)) {
		return io.ErrUnexpectedEOF
	}
	if msg.Version != ProtocolVersionMLS10 {
		return fmt.Errorf("mls: invalid protocol version %d", msg.Version)
	}

	if err := msg.WireFormat.Unmarshal(s); err != nil {
		return err
	}

	switch msg.WireFormat {
	case WireFormatMLSPublicMessage:
		msg.PublicMessage = new(PublicMessage)
		return msg.PublicMessage.Unmarshal(s)
	case WireFormatMLSPrivateMessage:
		msg.PrivateMessage = new(PrivateMessage)
		return msg.PrivateMessage.Unmarshal(s)
	case WireFormatMLSWelcome:
		msg.Welcome = new(Welcome)
		return msg.Welcome.Unmarshal(s)
	case WireFormatMLSGroupInfo:
		msg.GroupInfo = new(GroupInfo)
		return msg.GroupInfo.Unmarshal(s)
	case WireFormatMLSKeyPackage:
		msg.KeyPackage = new(KeyPackage)
		return msg.KeyPackage.Unmarshal(s)
	default:
		panic("unreachable")
	}
}

func (msg *MLSMessage) Marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(msg.Version))
	msg.WireFormat.Marshal(b)
	switch msg.WireFormat {
	case WireFormatMLSPublicMessage:
		msg.PublicMessage.Marshal(b)
	case WireFormatMLSPrivateMessage:
		msg.PrivateMessage.Marshal(b)
	case WireFormatMLSWelcome:
		msg.Welcome.Marshal(b)
	case WireFormatMLSGroupInfo:
		msg.GroupInfo.Marshal(b)
	case WireFormatMLSKeyPackage:
		msg.KeyPackage.Marshal(b)
	default:
		panic("unreachable")
	}
}

type AuthenticatedContent struct {
	WireFormat WireFormat
	Content    FramedContent
	Auth       FramedContentAuthData
}

func SignAuthenticatedContent(cs CipherSuite, signKey []byte, wf WireFormat, content *FramedContent, ctx *GroupContext) (*AuthenticatedContent, error) {
	authContent := AuthenticatedContent{
		WireFormat: wf,
		Content:    *content,
	}
	tbs := authContent.FramedContentTBS(ctx)
	signature, err := SignFramedContent(cs, signKey, tbs)
	if err != nil {
		return nil, err
	}
	authContent.Auth.Signature = signature
	return &authContent, nil
}

func (authContent *AuthenticatedContent) Unmarshal(s *cryptobyte.String) error {
	if err := authContent.WireFormat.Unmarshal(s); err != nil {
		return err
	}
	if err := authContent.Content.Unmarshal(s); err != nil {
		return err
	}
	if err := authContent.Auth.Unmarshal(s, authContent.Content.ContentType); err != nil {
		return err
	}
	return nil
}

func (authContent *AuthenticatedContent) Marshal(b *cryptobyte.Builder) {
	authContent.WireFormat.Marshal(b)
	authContent.Content.marshal(b)
	authContent.Auth.Marshal(b, authContent.Content.ContentType)
}

func (authContent *AuthenticatedContent) ConfirmedTranscriptHashInput() *ConfirmedTranscriptHashInput {
	return &ConfirmedTranscriptHashInput{
		WireFormat: authContent.WireFormat,
		Content:    authContent.Content,
		Signature:  authContent.Auth.Signature,
	}
}

func (authContent *AuthenticatedContent) FramedContentTBS(ctx *GroupContext) *FramedContentTBS {
	return &FramedContentTBS{
		Version:    ProtocolVersionMLS10,
		WireFormat: authContent.WireFormat,
		Content:    authContent.Content,
		Context:    ctx,
	}
}

func (authContent *AuthenticatedContent) VerifySignature(cs CipherSuite, verifKey []byte, ctx *GroupContext) bool {
	return authContent.Auth.VerifySignature(cs, verifKey, authContent.FramedContentTBS(ctx))
}

func (authContent *AuthenticatedContent) GenerateProposalRef(cs CipherSuite) (ProposalRef, error) {
	if authContent.Content.ContentType != contentTypeProposal {
		panic("mls: AuthenticatedContent is not a proposal")
	}

	var b cryptobyte.Builder
	authContent.Marshal(&b)
	raw, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	hash, err := cs.RefHash([]byte("MLS 1.0 Proposal Reference"), raw)
	if err != nil {
		return nil, err
	}

	return ProposalRef(hash), nil
}

type FramedContentAuthData struct {
	Signature       []byte
	ConfirmationTag []byte // for contentTypeCommit
}

func (authData *FramedContentAuthData) Unmarshal(s *cryptobyte.String, ct contentType) error {
	*authData = FramedContentAuthData{}

	if !ReadOpaqueVec(s, &authData.Signature) {
		return io.ErrUnexpectedEOF
	}

	if ct == contentTypeCommit {
		if !ReadOpaqueVec(s, &authData.ConfirmationTag) {
			return io.ErrUnexpectedEOF
		}
	}

	return nil
}

func (authData *FramedContentAuthData) Marshal(b *cryptobyte.Builder, ct contentType) {
	WriteOpaqueVec(b, authData.Signature)

	if ct == contentTypeCommit {
		WriteOpaqueVec(b, authData.ConfirmationTag)
	}
}

func (authData *FramedContentAuthData) VerifyConfirmationTag(cs CipherSuite, confirmationKey, confirmedTranscriptHash []byte) bool {
	if len(authData.ConfirmationTag) == 0 {
		return false
	}
	return cs.VerifyMAC(confirmationKey, confirmedTranscriptHash, authData.ConfirmationTag)
}

func (authData *FramedContentAuthData) VerifySignature(cs CipherSuite, verifKey []byte, content *FramedContentTBS) bool {
	rawContent, err := Marshal(content)
	if err != nil {
		return false
	}
	return cs.VerifyWithLabel(verifKey, []byte("FramedContentTBS"), rawContent, authData.Signature)
}

func SignFramedContent(cs CipherSuite, signKey []byte, content *FramedContentTBS) ([]byte, error) {
	rawContent, err := Marshal(content)
	if err != nil {
		return nil, err
	}
	return cs.SignWithLabel(signKey, []byte("FramedContentTBS"), rawContent)
}

type FramedContentTBS struct {
	Version    ProtocolVersion
	WireFormat WireFormat
	Content    FramedContent
	Context    *GroupContext // for senderTypeMember and senderTypeNewMemberCommit
}

func (content *FramedContentTBS) Marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(content.Version))
	content.WireFormat.Marshal(b)
	content.Content.marshal(b)
	switch content.Content.Sender.SenderType {
	case senderTypeMember, senderTypeNewMemberCommit:
		content.Context.Marshal(b)
	}
}

type PublicMessage struct {
	Content       FramedContent
	Auth          FramedContentAuthData
	MembershipTag []byte // for senderTypeMember
}

func SignPublicMessage(cs CipherSuite, signKey []byte, content *FramedContent, ctx *GroupContext) (*PublicMessage, error) {
	authContent, err := SignAuthenticatedContent(cs, signKey, WireFormatMLSPublicMessage, content, ctx)
	if err != nil {
		return nil, err
	}
	return &PublicMessage{
		Content: authContent.Content,
		Auth:    authContent.Auth,
	}, nil
}

func (msg *PublicMessage) Unmarshal(s *cryptobyte.String) error {
	*msg = PublicMessage{}

	if err := msg.Content.Unmarshal(s); err != nil {
		return err
	}
	if err := msg.Auth.Unmarshal(s, msg.Content.ContentType); err != nil {
		return err
	}

	if msg.Content.Sender.SenderType == senderTypeMember {
		if !ReadOpaqueVec(s, &msg.MembershipTag) {
			return io.ErrUnexpectedEOF
		}
	}

	return nil
}

func (msg *PublicMessage) Marshal(b *cryptobyte.Builder) {
	msg.Content.marshal(b)
	msg.Auth.Marshal(b, msg.Content.ContentType)

	if msg.Content.Sender.SenderType == senderTypeMember {
		WriteOpaqueVec(b, msg.MembershipTag)
	}
}

func (msg *PublicMessage) AuthenticatedContent() *AuthenticatedContent {
	return &AuthenticatedContent{
		WireFormat: WireFormatMLSPublicMessage,
		Content:    msg.Content,
		Auth:       msg.Auth,
	}
}

func (msg *PublicMessage) AuthenticatedContentTBM(ctx *GroupContext) *AuthenticatedContentTBM {
	return &AuthenticatedContentTBM{
		ContentTBS: *msg.AuthenticatedContent().FramedContentTBS(ctx),
		Auth:       msg.Auth,
	}
}

func (msg *PublicMessage) SignMembershipTag(cs CipherSuite, membershipKey []byte, ctx *GroupContext) error {
	if msg.Content.Sender.SenderType != senderTypeMember {
		return nil
	}
	rawAuthContentTBM, err := Marshal(msg.AuthenticatedContentTBM(ctx))
	if err != nil {
		return err
	}
	msg.MembershipTag = cs.SignMAC(membershipKey, rawAuthContentTBM)
	return nil
}

func (msg *PublicMessage) VerifyMembershipTag(cs CipherSuite, membershipKey []byte, ctx *GroupContext) bool {
	if msg.Content.Sender.SenderType != senderTypeMember {
		return true // there is no membership tag
	}
	rawAuthContentTBM, err := Marshal(msg.AuthenticatedContentTBM(ctx))
	if err != nil {
		return false
	}
	return cs.VerifyMAC(membershipKey, rawAuthContentTBM, msg.MembershipTag)
}

type AuthenticatedContentTBM struct {
	ContentTBS FramedContentTBS
	Auth       FramedContentAuthData
}

func (tbm *AuthenticatedContentTBM) Marshal(b *cryptobyte.Builder) {
	tbm.ContentTBS.Marshal(b)
	tbm.Auth.Marshal(b, tbm.ContentTBS.Content.ContentType)
}

type PrivateMessage struct {
	GroupID             GroupID
	Epoch               uint64
	ContentType         contentType
	AuthenticatedData   []byte
	EncryptedSenderData []byte
	Ciphertext          []byte
}

func EncryptPrivateMessage(cs CipherSuite, signPriv []byte, secret RatchetSecret, senderDataSecret []byte, content *FramedContent, senderData *SenderData, ctx *GroupContext) (*PrivateMessage, error) {
	ciphertext, err := EncryptPrivateMessageContent(cs, signPriv, secret, content, ctx, senderData.ReuseGuard)
	if err != nil {
		return nil, err
	}
	encryptedSenderData, err := EncryptSenderData(cs, senderDataSecret, senderData, content, ciphertext)
	if err != nil {
		return nil, err
	}
	return &PrivateMessage{
		GroupID:             content.GroupID,
		Epoch:               content.Epoch,
		ContentType:         content.ContentType,
		AuthenticatedData:   content.AuthenticatedData,
		EncryptedSenderData: encryptedSenderData,
		Ciphertext:          ciphertext,
	}, nil
}

func (msg *PrivateMessage) Unmarshal(s *cryptobyte.String) error {
	*msg = PrivateMessage{}
	ok := ReadOpaqueVec(s, (*[]byte)(&msg.GroupID)) &&
		s.ReadUint64(&msg.Epoch)
	if !ok {
		return io.ErrUnexpectedEOF
	}
	if err := msg.ContentType.unmarshal(s); err != nil {
		return err
	}
	ok = ReadOpaqueVec(s, &msg.AuthenticatedData) &&
		ReadOpaqueVec(s, &msg.EncryptedSenderData) &&
		ReadOpaqueVec(s, &msg.Ciphertext)
	if !ok {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (msg *PrivateMessage) Marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, []byte(msg.GroupID))
	b.AddUint64(msg.Epoch)
	msg.ContentType.marshal(b)
	WriteOpaqueVec(b, msg.AuthenticatedData)
	WriteOpaqueVec(b, msg.EncryptedSenderData)
	WriteOpaqueVec(b, msg.Ciphertext)
}

func (msg *PrivateMessage) DecryptSenderData(cs CipherSuite, senderDataSecret []byte) (*SenderData, error) {
	key, err := ExpandSenderDataKey(cs, senderDataSecret, msg.Ciphertext)
	if err != nil {
		return nil, err
	}
	nonce, err := ExpandSenderDataNonce(cs, senderDataSecret, msg.Ciphertext)
	if err != nil {
		return nil, err
	}

	aad := SenderDataAAD{
		GroupID:     msg.GroupID,
		Epoch:       msg.Epoch,
		ContentType: msg.ContentType,
	}
	rawAAD, err := Marshal(&aad)
	if err != nil {
		return nil, err
	}

	_, _, aead := cs.HPKE().Params()
	cipher, err := aead.New(key)
	if err != nil {
		return nil, err
	}

	rawSenderData, err := cipher.Open(nil, nonce, msg.EncryptedSenderData, rawAAD)
	if err != nil {
		return nil, err
	}

	var senderData SenderData
	if err := Unmarshal(rawSenderData, &senderData); err != nil {
		return nil, err
	}

	return &senderData, nil
}

func (msg *PrivateMessage) DecryptContent(cs CipherSuite, secret RatchetSecret, reuseGuard [4]byte) (*PrivateMessageContent, error) {
	key, nonce, err := DerivePrivateMessageKeyAndNonce(cs, secret, reuseGuard)
	if err != nil {
		return nil, err
	}

	aad := PrivateContentAAD{
		GroupID:           msg.GroupID,
		Epoch:             msg.Epoch,
		ContentType:       msg.ContentType,
		AuthenticatedData: msg.AuthenticatedData,
	}
	rawAAD, err := Marshal(&aad)
	if err != nil {
		return nil, err
	}

	_, _, aead := cs.HPKE().Params()
	cipher, err := aead.New(key)
	if err != nil {
		return nil, err
	}

	rawContent, err := cipher.Open(nil, nonce, msg.Ciphertext, rawAAD)
	if err != nil {
		return nil, err
	}

	s := cryptobyte.String(rawContent)
	var content PrivateMessageContent
	if err := content.Unmarshal(&s, msg.ContentType); err != nil {
		return nil, err
	}

	for _, v := range s {
		if v != 0 {
			return nil, fmt.Errorf("mls: padding contains non-zero bytes")
		}
	}

	return &content, nil
}

func DerivePrivateMessageKeyAndNonce(cs CipherSuite, secret RatchetSecret, reuseGuard [4]byte) (key, nonce []byte, err error) {
	key, err = secret.DeriveKey(cs)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = secret.DeriveNonce(cs)
	if err != nil {
		return nil, nil, err
	}

	for i := range reuseGuard {
		nonce[i] = nonce[i] ^ reuseGuard[i]
	}

	return key, nonce, nil
}

func (msg *PrivateMessage) AuthenticatedContent(senderData *SenderData, content *PrivateMessageContent) *AuthenticatedContent {
	return &AuthenticatedContent{
		WireFormat: WireFormatMLSPrivateMessage,
		Content: FramedContent{
			GroupID: msg.GroupID,
			Epoch:   msg.Epoch,
			Sender: Sender{
				SenderType: senderTypeMember,
				LeafIndex:  senderData.LeafIndex,
			},
			AuthenticatedData: msg.AuthenticatedData,
			ContentType:       msg.ContentType,
			ApplicationData:   content.ApplicationData,
			Proposal:          content.Proposal,
			Commit:            content.Commit,
		},
		Auth: content.Auth,
	}
}

type SenderDataAAD struct {
	GroupID     GroupID
	Epoch       uint64
	ContentType contentType
}

func (aad *SenderDataAAD) Marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, []byte(aad.GroupID))
	b.AddUint64(aad.Epoch)
	aad.ContentType.marshal(b)
}

type PrivateContentAAD struct {
	GroupID           GroupID
	Epoch             uint64
	ContentType       contentType
	AuthenticatedData []byte
}

func (aad *PrivateContentAAD) Marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, []byte(aad.GroupID))
	b.AddUint64(aad.Epoch)
	aad.ContentType.marshal(b)
	WriteOpaqueVec(b, aad.AuthenticatedData)
}

type PrivateMessageContent struct {
	ApplicationData []byte    // for contentTypeApplication
	Proposal        *Proposal // for contentTypeProposal
	Commit          *Commit   // for contentTypeCommit

	Auth FramedContentAuthData
}

func (content *PrivateMessageContent) Unmarshal(s *cryptobyte.String, ct contentType) error {
	*content = PrivateMessageContent{}

	var err error
	switch ct {
	case contentTypeApplication:
		if !ReadOpaqueVec(s, &content.ApplicationData) {
			err = io.ErrUnexpectedEOF
		}
	case contentTypeProposal:
		content.Proposal = new(Proposal)
		err = content.Proposal.Unmarshal(s)
	case contentTypeCommit:
		content.Commit = new(Commit)
		err = content.Commit.Unmarshal(s)
	default:
		panic("unreachable")
	}
	if err != nil {
		return err
	}

	return content.Auth.Unmarshal(s, ct)
}

func (content *PrivateMessageContent) Marshal(b *cryptobyte.Builder, ct contentType) {
	switch ct {
	case contentTypeApplication:
		WriteOpaqueVec(b, content.ApplicationData)
	case contentTypeProposal:
		content.Proposal.Marshal(b)
	case contentTypeCommit:
		content.Commit.Marshal(b)
	default:
		panic("unreachable")
	}
	content.Auth.Marshal(b, ct)
}

func EncryptPrivateMessageContent(cs CipherSuite, signKey []byte, secret RatchetSecret, content *FramedContent, ctx *GroupContext, reuseGuard [4]byte) ([]byte, error) {
	authContent, err := SignAuthenticatedContent(cs, signKey, WireFormatMLSPrivateMessage, content, ctx)
	if err != nil {
		return nil, err
	}

	privContent := PrivateMessageContent{
		ApplicationData: content.ApplicationData,
		Proposal:        content.Proposal,
		Commit:          content.Commit,
		Auth:            authContent.Auth,
	}
	var b cryptobyte.Builder
	privContent.Marshal(&b, content.ContentType)
	plaintext, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	key, nonce, err := DerivePrivateMessageKeyAndNonce(cs, secret, reuseGuard)
	if err != nil {
		return nil, err
	}

	aad := PrivateContentAAD{
		GroupID:           content.GroupID,
		Epoch:             content.Epoch,
		ContentType:       content.ContentType,
		AuthenticatedData: content.AuthenticatedData,
	}
	rawAAD, err := Marshal(&aad)
	if err != nil {
		return nil, err
	}

	_, _, aead := cs.HPKE().Params()
	cipher, err := aead.New(key)
	if err != nil {
		return nil, err
	}

	return cipher.Seal(nil, nonce, plaintext, rawAAD), nil
}

func EncryptSenderData(cs CipherSuite, senderDataSecret []byte, senderData *SenderData, content *FramedContent, ciphertext []byte) ([]byte, error) {
	key, err := ExpandSenderDataKey(cs, senderDataSecret, ciphertext)
	if err != nil {
		return nil, err
	}
	nonce, err := ExpandSenderDataNonce(cs, senderDataSecret, ciphertext)
	if err != nil {
		return nil, err
	}

	aad := SenderDataAAD{
		GroupID:     content.GroupID,
		Epoch:       content.Epoch,
		ContentType: content.ContentType,
	}
	rawAAD, err := Marshal(&aad)
	if err != nil {
		return nil, err
	}

	_, _, aead := cs.HPKE().Params()
	cipher, err := aead.New(key)
	if err != nil {
		return nil, err
	}

	rawSenderData, err := Marshal(senderData)
	if err != nil {
		return nil, err
	}

	return cipher.Seal(nil, nonce, rawSenderData, rawAAD), nil
}

type SenderData struct {
	LeafIndex  LeafIndex
	Generation uint32
	ReuseGuard [4]byte
}

func NewSenderData(leafIndex LeafIndex, generation uint32) (*SenderData, error) {
	data := SenderData{
		LeafIndex:  leafIndex,
		Generation: generation,
	}
	if _, err := rand.Read(data.ReuseGuard[:]); err != nil {
		return nil, err
	}
	return &data, nil
}

func (data *SenderData) Unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint32((*uint32)(&data.LeafIndex)) || !s.ReadUint32(&data.Generation) || !s.CopyBytes(data.ReuseGuard[:]) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (data *SenderData) Marshal(b *cryptobyte.Builder) {
	b.AddUint32(uint32(data.LeafIndex))
	b.AddUint32(data.Generation)
	b.AddBytes(data.ReuseGuard[:])
}

func ExpandSenderDataKey(cs CipherSuite, senderDataSecret, ciphertext []byte) ([]byte, error) {
	_, _, aead := cs.HPKE().Params()
	ciphertextSample := sampleCiphertext(cs, ciphertext)
	return cs.ExpandWithLabel(senderDataSecret, []byte("key"), ciphertextSample, uint16(aead.KeySize()))
}

func ExpandSenderDataNonce(cs CipherSuite, senderDataSecret, ciphertext []byte) ([]byte, error) {
	_, _, aead := cs.HPKE().Params()
	ciphertextSample := sampleCiphertext(cs, ciphertext)
	return cs.ExpandWithLabel(senderDataSecret, []byte("nonce"), ciphertextSample, uint16(aead.NonceSize()))
}

func sampleCiphertext(cs CipherSuite, ciphertext []byte) []byte {
	_, kdf, _ := cs.HPKE().Params()
	n := kdf.ExtractSize()
	if len(ciphertext) < n {
		return ciphertext
	}
	return ciphertext[:n]
}
