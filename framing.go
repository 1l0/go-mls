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
	senderType  senderType
	leafIndex   leafIndex // for senderTypeMember
	senderIndex uint32    // for senderTypeExternal
}

func (snd *Sender) Unmarshal(s *cryptobyte.String) error {
	*snd = Sender{}
	if err := snd.senderType.unmarshal(s); err != nil {
		return err
	}
	switch snd.senderType {
	case senderTypeMember:
		if !s.ReadUint32((*uint32)(&snd.leafIndex)) {
			return io.ErrUnexpectedEOF
		}
	case senderTypeExternal:
		if !s.ReadUint32(&snd.senderIndex) {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func (snd *Sender) Marshal(b *cryptobyte.Builder) {
	snd.senderType.marshal(b)
	switch snd.senderType {
	case senderTypeMember:
		b.AddUint32(uint32(snd.leafIndex))
	case senderTypeExternal:
		b.AddUint32(snd.senderIndex)
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
	groupID           GroupID
	epoch             uint64
	sender            Sender
	authenticatedData []byte

	contentType     contentType
	applicationData []byte    // for contentTypeApplication
	proposal        *Proposal // for contentTypeProposal
	commit          *Commit   // for contentTypeCommit
}

func (content *FramedContent) Unmarshal(s *cryptobyte.String) error {
	*content = FramedContent{}

	if !ReadOpaqueVec(s, (*[]byte)(&content.groupID)) || !s.ReadUint64(&content.epoch) {
		return io.ErrUnexpectedEOF
	}
	if err := content.sender.Unmarshal(s); err != nil {
		return err
	}
	if !ReadOpaqueVec(s, &content.authenticatedData) {
		return io.ErrUnexpectedEOF
	}
	if err := content.contentType.unmarshal(s); err != nil {
		return err
	}

	switch content.contentType {
	case contentTypeApplication:
		if !ReadOpaqueVec(s, &content.applicationData) {
			return io.ErrUnexpectedEOF
		}
		return nil
	case contentTypeProposal:
		content.proposal = new(Proposal)
		return content.proposal.Unmarshal(s)
	case contentTypeCommit:
		content.commit = new(Commit)
		return content.commit.Unmarshal(s)
	default:
		panic("unreachable")
	}
}

func (content *FramedContent) marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, []byte(content.groupID))
	b.AddUint64(content.epoch)
	content.sender.Marshal(b)
	WriteOpaqueVec(b, content.authenticatedData)
	content.contentType.marshal(b)
	switch content.contentType {
	case contentTypeApplication:
		WriteOpaqueVec(b, content.applicationData)
	case contentTypeProposal:
		content.proposal.Marshal(b)
	case contentTypeCommit:
		content.commit.Marshal(b)
	default:
		panic("unreachable")
	}
}

type MLSMessage struct {
	version        ProtocolVersion
	wireFormat     WireFormat
	publicMessage  *PublicMessage  // for wireFormatMLSPublicMessage
	privateMessage *PrivateMessage // for wireFormatMLSPrivateMessage
	welcome        *Welcome        // for wireFormatMLSWelcome
	groupInfo      *GroupInfo      // for wireFormatMLSGroupInfo
	keyPackage     *KeyPackage     // for wireFormatMLSKeyPackage
}

func (msg *MLSMessage) Unmarshal(s *cryptobyte.String) error {
	*msg = MLSMessage{}

	if !s.ReadUint16((*uint16)(&msg.version)) {
		return io.ErrUnexpectedEOF
	}
	if msg.version != ProtocolVersionMLS10 {
		return fmt.Errorf("mls: invalid protocol version %d", msg.version)
	}

	if err := msg.wireFormat.Unmarshal(s); err != nil {
		return err
	}

	switch msg.wireFormat {
	case WireFormatMLSPublicMessage:
		msg.publicMessage = new(PublicMessage)
		return msg.publicMessage.Unmarshal(s)
	case WireFormatMLSPrivateMessage:
		msg.privateMessage = new(PrivateMessage)
		return msg.privateMessage.Unmarshal(s)
	case WireFormatMLSWelcome:
		msg.welcome = new(Welcome)
		return msg.welcome.Unmarshal(s)
	case WireFormatMLSGroupInfo:
		msg.groupInfo = new(GroupInfo)
		return msg.groupInfo.Unmarshal(s)
	case WireFormatMLSKeyPackage:
		msg.keyPackage = new(KeyPackage)
		return msg.keyPackage.Unmarshal(s)
	default:
		panic("unreachable")
	}
}

func (msg *MLSMessage) Marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(msg.version))
	msg.wireFormat.Marshal(b)
	switch msg.wireFormat {
	case WireFormatMLSPublicMessage:
		msg.publicMessage.Marshal(b)
	case WireFormatMLSPrivateMessage:
		msg.privateMessage.Marshal(b)
	case WireFormatMLSWelcome:
		msg.welcome.Marshal(b)
	case WireFormatMLSGroupInfo:
		msg.groupInfo.Marshal(b)
	case WireFormatMLSKeyPackage:
		msg.keyPackage.Marshal(b)
	default:
		panic("unreachable")
	}
}

type AuthenticatedContent struct {
	wireFormat WireFormat
	content    FramedContent
	auth       FramedContentAuthData
}

func SignAuthenticatedContent(cs CipherSuite, signKey []byte, wf WireFormat, content *FramedContent, ctx *GroupContext) (*AuthenticatedContent, error) {
	authContent := AuthenticatedContent{
		wireFormat: wf,
		content:    *content,
	}
	tbs := authContent.FramedContentTBS(ctx)
	signature, err := SignFramedContent(cs, signKey, tbs)
	if err != nil {
		return nil, err
	}
	authContent.auth.signature = signature
	return &authContent, nil
}

func (authContent *AuthenticatedContent) Unmarshal(s *cryptobyte.String) error {
	if err := authContent.wireFormat.Unmarshal(s); err != nil {
		return err
	}
	if err := authContent.content.Unmarshal(s); err != nil {
		return err
	}
	if err := authContent.auth.Unmarshal(s, authContent.content.contentType); err != nil {
		return err
	}
	return nil
}

func (authContent *AuthenticatedContent) Marshal(b *cryptobyte.Builder) {
	authContent.wireFormat.Marshal(b)
	authContent.content.marshal(b)
	authContent.auth.Marshal(b, authContent.content.contentType)
}

func (authContent *AuthenticatedContent) ConfirmedTranscriptHashInput() *ConfirmedTranscriptHashInput {
	return &ConfirmedTranscriptHashInput{
		wireFormat: authContent.wireFormat,
		content:    authContent.content,
		signature:  authContent.auth.signature,
	}
}

func (authContent *AuthenticatedContent) FramedContentTBS(ctx *GroupContext) *FramedContentTBS {
	return &FramedContentTBS{
		version:    ProtocolVersionMLS10,
		wireFormat: authContent.wireFormat,
		content:    authContent.content,
		context:    ctx,
	}
}

func (authContent *AuthenticatedContent) VerifySignature(cs CipherSuite, verifKey []byte, ctx *GroupContext) bool {
	return authContent.auth.VerifySignature(cs, verifKey, authContent.FramedContentTBS(ctx))
}

func (authContent *AuthenticatedContent) GenerateProposalRef(cs CipherSuite) (ProposalRef, error) {
	if authContent.content.contentType != contentTypeProposal {
		panic("mls: AuthenticatedContent is not a proposal")
	}

	var b cryptobyte.Builder
	authContent.Marshal(&b)
	raw, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	hash, err := cs.refHash([]byte("MLS 1.0 Proposal Reference"), raw)
	if err != nil {
		return nil, err
	}

	return ProposalRef(hash), nil
}

type FramedContentAuthData struct {
	signature       []byte
	confirmationTag []byte // for contentTypeCommit
}

func (authData *FramedContentAuthData) Unmarshal(s *cryptobyte.String, ct contentType) error {
	*authData = FramedContentAuthData{}

	if !ReadOpaqueVec(s, &authData.signature) {
		return io.ErrUnexpectedEOF
	}

	if ct == contentTypeCommit {
		if !ReadOpaqueVec(s, &authData.confirmationTag) {
			return io.ErrUnexpectedEOF
		}
	}

	return nil
}

func (authData *FramedContentAuthData) Marshal(b *cryptobyte.Builder, ct contentType) {
	WriteOpaqueVec(b, authData.signature)

	if ct == contentTypeCommit {
		WriteOpaqueVec(b, authData.confirmationTag)
	}
}

func (authData *FramedContentAuthData) VerifyConfirmationTag(cs CipherSuite, confirmationKey, confirmedTranscriptHash []byte) bool {
	if len(authData.confirmationTag) == 0 {
		return false
	}
	return cs.verifyMAC(confirmationKey, confirmedTranscriptHash, authData.confirmationTag)
}

func (authData *FramedContentAuthData) VerifySignature(cs CipherSuite, verifKey []byte, content *FramedContentTBS) bool {
	rawContent, err := Marshal(content)
	if err != nil {
		return false
	}
	return cs.VerifyWithLabel(verifKey, []byte("FramedContentTBS"), rawContent, authData.signature)
}

func SignFramedContent(cs CipherSuite, signKey []byte, content *FramedContentTBS) ([]byte, error) {
	rawContent, err := Marshal(content)
	if err != nil {
		return nil, err
	}
	return cs.SignWithLabel(signKey, []byte("FramedContentTBS"), rawContent)
}

type FramedContentTBS struct {
	version    ProtocolVersion
	wireFormat WireFormat
	content    FramedContent
	context    *GroupContext // for senderTypeMember and senderTypeNewMemberCommit
}

func (content *FramedContentTBS) Marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(content.version))
	content.wireFormat.Marshal(b)
	content.content.marshal(b)
	switch content.content.sender.senderType {
	case senderTypeMember, senderTypeNewMemberCommit:
		content.context.Marshal(b)
	}
}

type PublicMessage struct {
	content       FramedContent
	auth          FramedContentAuthData
	membershipTag []byte // for senderTypeMember
}

func SignPublicMessage(cs CipherSuite, signKey []byte, content *FramedContent, ctx *GroupContext) (*PublicMessage, error) {
	authContent, err := SignAuthenticatedContent(cs, signKey, WireFormatMLSPublicMessage, content, ctx)
	if err != nil {
		return nil, err
	}
	return &PublicMessage{
		content: authContent.content,
		auth:    authContent.auth,
	}, nil
}

func (msg *PublicMessage) Unmarshal(s *cryptobyte.String) error {
	*msg = PublicMessage{}

	if err := msg.content.Unmarshal(s); err != nil {
		return err
	}
	if err := msg.auth.Unmarshal(s, msg.content.contentType); err != nil {
		return err
	}

	if msg.content.sender.senderType == senderTypeMember {
		if !ReadOpaqueVec(s, &msg.membershipTag) {
			return io.ErrUnexpectedEOF
		}
	}

	return nil
}

func (msg *PublicMessage) Marshal(b *cryptobyte.Builder) {
	msg.content.marshal(b)
	msg.auth.Marshal(b, msg.content.contentType)

	if msg.content.sender.senderType == senderTypeMember {
		WriteOpaqueVec(b, msg.membershipTag)
	}
}

func (msg *PublicMessage) AuthenticatedContent() *AuthenticatedContent {
	return &AuthenticatedContent{
		wireFormat: WireFormatMLSPublicMessage,
		content:    msg.content,
		auth:       msg.auth,
	}
}

func (msg *PublicMessage) AuthenticatedContentTBM(ctx *GroupContext) *AuthenticatedContentTBM {
	return &AuthenticatedContentTBM{
		contentTBS: *msg.AuthenticatedContent().FramedContentTBS(ctx),
		auth:       msg.auth,
	}
}

func (msg *PublicMessage) SignMembershipTag(cs CipherSuite, membershipKey []byte, ctx *GroupContext) error {
	if msg.content.sender.senderType != senderTypeMember {
		return nil
	}
	rawAuthContentTBM, err := Marshal(msg.AuthenticatedContentTBM(ctx))
	if err != nil {
		return err
	}
	msg.membershipTag = cs.signMAC(membershipKey, rawAuthContentTBM)
	return nil
}

func (msg *PublicMessage) VerifyMembershipTag(cs CipherSuite, membershipKey []byte, ctx *GroupContext) bool {
	if msg.content.sender.senderType != senderTypeMember {
		return true // there is no membership tag
	}
	rawAuthContentTBM, err := Marshal(msg.AuthenticatedContentTBM(ctx))
	if err != nil {
		return false
	}
	return cs.verifyMAC(membershipKey, rawAuthContentTBM, msg.membershipTag)
}

type AuthenticatedContentTBM struct {
	contentTBS FramedContentTBS
	auth       FramedContentAuthData
}

func (tbm *AuthenticatedContentTBM) Marshal(b *cryptobyte.Builder) {
	tbm.contentTBS.Marshal(b)
	tbm.auth.Marshal(b, tbm.contentTBS.content.contentType)
}

type PrivateMessage struct {
	groupID             GroupID
	epoch               uint64
	contentType         contentType
	authenticatedData   []byte
	encryptedSenderData []byte
	ciphertext          []byte
}

func EncryptPrivateMessage(cs CipherSuite, signPriv []byte, secret RatchetSecret, senderDataSecret []byte, content *FramedContent, senderData *SenderData, ctx *GroupContext) (*PrivateMessage, error) {
	ciphertext, err := EncryptPrivateMessageContent(cs, signPriv, secret, content, ctx, senderData.reuseGuard)
	if err != nil {
		return nil, err
	}
	encryptedSenderData, err := EncryptSenderData(cs, senderDataSecret, senderData, content, ciphertext)
	if err != nil {
		return nil, err
	}
	return &PrivateMessage{
		groupID:             content.groupID,
		epoch:               content.epoch,
		contentType:         content.contentType,
		authenticatedData:   content.authenticatedData,
		encryptedSenderData: encryptedSenderData,
		ciphertext:          ciphertext,
	}, nil
}

func (msg *PrivateMessage) Unmarshal(s *cryptobyte.String) error {
	*msg = PrivateMessage{}
	ok := ReadOpaqueVec(s, (*[]byte)(&msg.groupID)) &&
		s.ReadUint64(&msg.epoch)
	if !ok {
		return io.ErrUnexpectedEOF
	}
	if err := msg.contentType.unmarshal(s); err != nil {
		return err
	}
	ok = ReadOpaqueVec(s, &msg.authenticatedData) &&
		ReadOpaqueVec(s, &msg.encryptedSenderData) &&
		ReadOpaqueVec(s, &msg.ciphertext)
	if !ok {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (msg *PrivateMessage) Marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, []byte(msg.groupID))
	b.AddUint64(msg.epoch)
	msg.contentType.marshal(b)
	WriteOpaqueVec(b, msg.authenticatedData)
	WriteOpaqueVec(b, msg.encryptedSenderData)
	WriteOpaqueVec(b, msg.ciphertext)
}

func (msg *PrivateMessage) DecryptSenderData(cs CipherSuite, senderDataSecret []byte) (*SenderData, error) {
	key, err := ExpandSenderDataKey(cs, senderDataSecret, msg.ciphertext)
	if err != nil {
		return nil, err
	}
	nonce, err := ExpandSenderDataNonce(cs, senderDataSecret, msg.ciphertext)
	if err != nil {
		return nil, err
	}

	aad := senderDataAAD{
		groupID:     msg.groupID,
		epoch:       msg.epoch,
		contentType: msg.contentType,
	}
	rawAAD, err := Marshal(&aad)
	if err != nil {
		return nil, err
	}

	_, _, aead := cs.hpke().Params()
	cipher, err := aead.New(key)
	if err != nil {
		return nil, err
	}

	rawSenderData, err := cipher.Open(nil, nonce, msg.encryptedSenderData, rawAAD)
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

	aad := privateContentAAD{
		groupID:           msg.groupID,
		epoch:             msg.epoch,
		contentType:       msg.contentType,
		authenticatedData: msg.authenticatedData,
	}
	rawAAD, err := Marshal(&aad)
	if err != nil {
		return nil, err
	}

	_, _, aead := cs.hpke().Params()
	cipher, err := aead.New(key)
	if err != nil {
		return nil, err
	}

	rawContent, err := cipher.Open(nil, nonce, msg.ciphertext, rawAAD)
	if err != nil {
		return nil, err
	}

	s := cryptobyte.String(rawContent)
	var content PrivateMessageContent
	if err := content.Unmarshal(&s, msg.contentType); err != nil {
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
		wireFormat: WireFormatMLSPrivateMessage,
		content: FramedContent{
			groupID: msg.groupID,
			epoch:   msg.epoch,
			sender: Sender{
				senderType: senderTypeMember,
				leafIndex:  senderData.leafIndex,
			},
			authenticatedData: msg.authenticatedData,
			contentType:       msg.contentType,
			applicationData:   content.applicationData,
			proposal:          content.proposal,
			commit:            content.commit,
		},
		auth: content.auth,
	}
}

type senderDataAAD struct {
	groupID     GroupID
	epoch       uint64
	contentType contentType
}

func (aad *senderDataAAD) Marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, []byte(aad.groupID))
	b.AddUint64(aad.epoch)
	aad.contentType.marshal(b)
}

type privateContentAAD struct {
	groupID           GroupID
	epoch             uint64
	contentType       contentType
	authenticatedData []byte
}

func (aad *privateContentAAD) Marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, []byte(aad.groupID))
	b.AddUint64(aad.epoch)
	aad.contentType.marshal(b)
	WriteOpaqueVec(b, aad.authenticatedData)
}

type PrivateMessageContent struct {
	applicationData []byte    // for contentTypeApplication
	proposal        *Proposal // for contentTypeProposal
	commit          *Commit   // for contentTypeCommit

	auth FramedContentAuthData
}

func (content *PrivateMessageContent) Unmarshal(s *cryptobyte.String, ct contentType) error {
	*content = PrivateMessageContent{}

	var err error
	switch ct {
	case contentTypeApplication:
		if !ReadOpaqueVec(s, &content.applicationData) {
			err = io.ErrUnexpectedEOF
		}
	case contentTypeProposal:
		content.proposal = new(Proposal)
		err = content.proposal.Unmarshal(s)
	case contentTypeCommit:
		content.commit = new(Commit)
		err = content.commit.Unmarshal(s)
	default:
		panic("unreachable")
	}
	if err != nil {
		return err
	}

	return content.auth.Unmarshal(s, ct)
}

func (content *PrivateMessageContent) Marshal(b *cryptobyte.Builder, ct contentType) {
	switch ct {
	case contentTypeApplication:
		WriteOpaqueVec(b, content.applicationData)
	case contentTypeProposal:
		content.proposal.Marshal(b)
	case contentTypeCommit:
		content.commit.Marshal(b)
	default:
		panic("unreachable")
	}
	content.auth.Marshal(b, ct)
}

func EncryptPrivateMessageContent(cs CipherSuite, signKey []byte, secret RatchetSecret, content *FramedContent, ctx *GroupContext, reuseGuard [4]byte) ([]byte, error) {
	authContent, err := SignAuthenticatedContent(cs, signKey, WireFormatMLSPrivateMessage, content, ctx)
	if err != nil {
		return nil, err
	}

	privContent := PrivateMessageContent{
		applicationData: content.applicationData,
		proposal:        content.proposal,
		commit:          content.commit,
		auth:            authContent.auth,
	}
	var b cryptobyte.Builder
	privContent.Marshal(&b, content.contentType)
	plaintext, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	key, nonce, err := DerivePrivateMessageKeyAndNonce(cs, secret, reuseGuard)
	if err != nil {
		return nil, err
	}

	aad := privateContentAAD{
		groupID:           content.groupID,
		epoch:             content.epoch,
		contentType:       content.contentType,
		authenticatedData: content.authenticatedData,
	}
	rawAAD, err := Marshal(&aad)
	if err != nil {
		return nil, err
	}

	_, _, aead := cs.hpke().Params()
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

	aad := senderDataAAD{
		groupID:     content.groupID,
		epoch:       content.epoch,
		contentType: content.contentType,
	}
	rawAAD, err := Marshal(&aad)
	if err != nil {
		return nil, err
	}

	_, _, aead := cs.hpke().Params()
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
	leafIndex  leafIndex
	generation uint32
	reuseGuard [4]byte
}

func NewSenderData(leafIndex leafIndex, generation uint32) (*SenderData, error) {
	data := SenderData{
		leafIndex:  leafIndex,
		generation: generation,
	}
	if _, err := rand.Read(data.reuseGuard[:]); err != nil {
		return nil, err
	}
	return &data, nil
}

func (data *SenderData) Unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint32((*uint32)(&data.leafIndex)) || !s.ReadUint32(&data.generation) || !s.CopyBytes(data.reuseGuard[:]) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (data *SenderData) Marshal(b *cryptobyte.Builder) {
	b.AddUint32(uint32(data.leafIndex))
	b.AddUint32(data.generation)
	b.AddBytes(data.reuseGuard[:])
}

func ExpandSenderDataKey(cs CipherSuite, senderDataSecret, ciphertext []byte) ([]byte, error) {
	_, _, aead := cs.hpke().Params()
	ciphertextSample := sampleCiphertext(cs, ciphertext)
	return cs.ExpandWithLabel(senderDataSecret, []byte("key"), ciphertextSample, uint16(aead.KeySize()))
}

func ExpandSenderDataNonce(cs CipherSuite, senderDataSecret, ciphertext []byte) ([]byte, error) {
	_, _, aead := cs.hpke().Params()
	ciphertextSample := sampleCiphertext(cs, ciphertext)
	return cs.ExpandWithLabel(senderDataSecret, []byte("nonce"), ciphertextSample, uint16(aead.NonceSize()))
}

func sampleCiphertext(cs CipherSuite, ciphertext []byte) []byte {
	_, kdf, _ := cs.hpke().Params()
	n := kdf.ExtractSize()
	if len(ciphertext) < n {
		return ciphertext
	}
	return ciphertext[:n]
}
