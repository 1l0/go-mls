package mls

import (
	"bytes"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

// http://www.iana.org/assignments/mls/mls.xhtml#mls-proposal-types
type ProposalType uint16

const (
	ProposalTypeAdd                    ProposalType = 0x0001
	ProposalTypeUpdate                 ProposalType = 0x0002
	ProposalTypeRemove                 ProposalType = 0x0003
	ProposalTypePSK                    ProposalType = 0x0004
	ProposalTypeReinit                 ProposalType = 0x0005
	ProposalTypeExternalInit           ProposalType = 0x0006
	ProposalTypeGroupContextExtensions ProposalType = 0x0007
)

func (t *ProposalType) Unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint16((*uint16)(t)) {
		return io.ErrUnexpectedEOF
	}
	switch *t {
	case ProposalTypeAdd, ProposalTypeUpdate, ProposalTypeRemove, ProposalTypePSK, ProposalTypeReinit, ProposalTypeExternalInit, ProposalTypeGroupContextExtensions:
		return nil
	default:
		return fmt.Errorf("mls: invalid proposal type %d", *t)
	}
}

func (t ProposalType) Marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(t))
}

type Proposal struct {
	proposalType           ProposalType
	add                    *Add                    // for proposalTypeAdd
	update                 *Update                 // for proposalTypeUpdate
	remove                 *Remove                 // for proposalTypeRemove
	preSharedKey           *PreSharedKey           // for proposalTypePSK
	reInit                 *ReInit                 // for proposalTypeReinit
	externalInit           *ExternalInit           // for proposalTypeExternalInit
	groupContextExtensions *GroupContextExtensions // for proposalTypeGroupContextExtensions
}

func (prop *Proposal) Unmarshal(s *cryptobyte.String) error {
	*prop = Proposal{}
	if err := prop.proposalType.Unmarshal(s); err != nil {
		return err
	}
	switch prop.proposalType {
	case ProposalTypeAdd:
		prop.add = new(Add)
		return prop.add.Unmarshal(s)
	case ProposalTypeUpdate:
		prop.update = new(Update)
		return prop.update.Unmarshal(s)
	case ProposalTypeRemove:
		prop.remove = new(Remove)
		return prop.remove.Unmarshal(s)
	case ProposalTypePSK:
		prop.preSharedKey = new(PreSharedKey)
		return prop.preSharedKey.Unmarshal(s)
	case ProposalTypeReinit:
		prop.reInit = new(ReInit)
		return prop.reInit.Unmarshal(s)
	case ProposalTypeExternalInit:
		prop.externalInit = new(ExternalInit)
		return prop.externalInit.Unmarshal(s)
	case ProposalTypeGroupContextExtensions:
		prop.groupContextExtensions = new(GroupContextExtensions)
		return prop.groupContextExtensions.Unmarshal(s)
	default:
		panic("unreachable")
	}
}

func (prop *Proposal) Marshal(b *cryptobyte.Builder) {
	prop.proposalType.Marshal(b)
	switch prop.proposalType {
	case ProposalTypeAdd:
		prop.add.Marshal(b)
	case ProposalTypeUpdate:
		prop.update.Marshal(b)
	case ProposalTypeRemove:
		prop.remove.Marshal(b)
	case ProposalTypePSK:
		prop.preSharedKey.Marshal(b)
	case ProposalTypeReinit:
		prop.reInit.Marshal(b)
	case ProposalTypeExternalInit:
		prop.externalInit.Marshal(b)
	case ProposalTypeGroupContextExtensions:
		prop.groupContextExtensions.Marshal(b)
	default:
		panic("unreachable")
	}
}

type Add struct {
	keyPackage KeyPackage
}

func (a *Add) Unmarshal(s *cryptobyte.String) error {
	*a = Add{}
	return a.keyPackage.Unmarshal(s)
}

func (a *Add) Marshal(b *cryptobyte.Builder) {
	a.keyPackage.Marshal(b)
}

type Update struct {
	leafNode LeafNode
}

func (upd *Update) Unmarshal(s *cryptobyte.String) error {
	*upd = Update{}
	return upd.leafNode.Unmarshal(s)
}

func (upd *Update) Marshal(b *cryptobyte.Builder) {
	upd.leafNode.Marshal(b)
}

type Remove struct {
	removed leafIndex
}

func (rm *Remove) Unmarshal(s *cryptobyte.String) error {
	*rm = Remove{}
	if !s.ReadUint32((*uint32)(&rm.removed)) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (rm *Remove) Marshal(b *cryptobyte.Builder) {
	b.AddUint32(uint32(rm.removed))
}

type PreSharedKey struct {
	psk PreSharedKeyID
}

func (psk *PreSharedKey) Unmarshal(s *cryptobyte.String) error {
	*psk = PreSharedKey{}
	return psk.psk.Unmarshal(s)
}

func (psk *PreSharedKey) Marshal(b *cryptobyte.Builder) {
	psk.psk.Marshal(b)
}

type ReInit struct {
	groupID     GroupID
	version     ProtocolVersion
	cipherSuite CipherSuite
	extensions  []Extension
}

func (ri *ReInit) Unmarshal(s *cryptobyte.String) error {
	*ri = ReInit{}

	if !ReadOpaqueVec(s, (*[]byte)(&ri.groupID)) || !s.ReadUint16((*uint16)(&ri.version)) || !s.ReadUint16((*uint16)(&ri.cipherSuite)) {
		return io.ErrUnexpectedEOF
	}

	exts, err := UnmarshalExtensionVec(s)
	if err != nil {
		return err
	}
	ri.extensions = exts

	return nil
}

func (ri *ReInit) Marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, []byte(ri.groupID))
	b.AddUint16(uint16(ri.version))
	b.AddUint16(uint16(ri.cipherSuite))
	MarshalExtensionVec(b, ri.extensions)
}

type ExternalInit struct {
	kemOutput []byte
}

func (ei *ExternalInit) Unmarshal(s *cryptobyte.String) error {
	*ei = ExternalInit{}
	if !ReadOpaqueVec(s, &ei.kemOutput) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (ei *ExternalInit) Marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, ei.kemOutput)
}

type GroupContextExtensions struct {
	extensions []Extension
}

func (exts *GroupContextExtensions) Unmarshal(s *cryptobyte.String) error {
	*exts = GroupContextExtensions{}

	l, err := UnmarshalExtensionVec(s)
	if err != nil {
		return err
	}
	exts.extensions = l

	return nil
}

func (exts *GroupContextExtensions) Marshal(b *cryptobyte.Builder) {
	MarshalExtensionVec(b, exts.extensions)
}

type ProposalOrRefType uint8

const (
	ProposalOrRefTypeProposal  ProposalOrRefType = 1
	ProposalOrRefTypeReference ProposalOrRefType = 2
)

func (t *ProposalOrRefType) Unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint8((*uint8)(t)) {
		return io.ErrUnexpectedEOF
	}
	switch *t {
	case ProposalOrRefTypeProposal, ProposalOrRefTypeReference:
		return nil
	default:
		return fmt.Errorf("mls: invalid proposal or ref type %d", *t)
	}
}

func (t ProposalOrRefType) Marshal(b *cryptobyte.Builder) {
	b.AddUint8(uint8(t))
}

type ProposalRef []byte

func (ref ProposalRef) Equal(other ProposalRef) bool {
	return bytes.Equal([]byte(ref), []byte(other))
}

type ProposalOrRef struct {
	typ       ProposalOrRefType
	proposal  *Proposal   // for proposalOrRefTypeProposal
	reference ProposalRef // for proposalOrRefTypeReference
}

func (propOrRef *ProposalOrRef) Unmarshal(s *cryptobyte.String) error {
	*propOrRef = ProposalOrRef{}

	if err := propOrRef.typ.Unmarshal(s); err != nil {
		return err
	}

	switch propOrRef.typ {
	case ProposalOrRefTypeProposal:
		propOrRef.proposal = new(Proposal)
		return propOrRef.proposal.Unmarshal(s)
	case ProposalOrRefTypeReference:
		if !ReadOpaqueVec(s, (*[]byte)(&propOrRef.reference)) {
			return io.ErrUnexpectedEOF
		}
		return nil
	default:
		panic("unreachable")
	}
}

func (propOrRef *ProposalOrRef) Marshal(b *cryptobyte.Builder) {
	propOrRef.typ.Marshal(b)
	switch propOrRef.typ {
	case ProposalOrRefTypeProposal:
		propOrRef.proposal.Marshal(b)
	case ProposalOrRefTypeReference:
		WriteOpaqueVec(b, []byte(propOrRef.reference))
	default:
		panic("unreachable")
	}
}

type Commit struct {
	proposals []ProposalOrRef
	path      *UpdatePath // optional
}

func (c *Commit) Unmarshal(s *cryptobyte.String) error {
	*c = Commit{}

	err := ReadVector(s, func(s *cryptobyte.String) error {
		var propOrRef ProposalOrRef
		if err := propOrRef.Unmarshal(s); err != nil {
			return err
		}
		c.proposals = append(c.proposals, propOrRef)
		return nil
	})
	if err != nil {
		return err
	}

	var hasPath bool
	if !ReadOptional(s, &hasPath) {
		return io.ErrUnexpectedEOF
	} else if hasPath {
		c.path = new(UpdatePath)
		if err := c.path.Unmarshal(s); err != nil {
			return err
		}
	}

	return nil
}

func (c *Commit) Marshal(b *cryptobyte.Builder) {
	WriteVector(b, len(c.proposals), func(b *cryptobyte.Builder, i int) {
		c.proposals[i].Marshal(b)
	})
	WriteOptional(b, c.path != nil)
	if c.path != nil {
		c.path.Marshal(b)
	}
}

// VerifyProposalList ensures that a list of proposals passes the checks for a
// regular commit described in section 12.2.
//
// It does not perform all checks:
//
//   - It does not check the validity of individual proposals (section 12.1).
//   - It does not check whether members in add proposals are already part of
//     the group.
//   - It does not check whether non-default proposal types are supported by
//     all members of the group who will process the commit.
//   - It does not check whether the ratchet tree is valid after processing the
//     commit.
func VerifyProposalList(proposals []Proposal, senders []leafIndex, committer leafIndex) error {
	if len(proposals) != len(senders) {
		panic("unreachable")
	}

	add := make(map[string]struct{})
	updateOrRemove := make(map[leafIndex]struct{})
	psk := make(map[string]struct{})
	groupContextExtensions := false
	for i, prop := range proposals {
		sender := senders[i]

		switch prop.proposalType {
		case ProposalTypeAdd:
			k := string(prop.add.keyPackage.LeafNode.signatureKey)
			if _, dup := add[k]; dup {
				return fmt.Errorf("mls: multiple add proposals have the same signature key")
			}
			add[k] = struct{}{}
		case ProposalTypeUpdate:
			if sender == committer {
				return fmt.Errorf("mls: update proposal generated by the committer")
			}
			if _, dup := updateOrRemove[sender]; dup {
				return fmt.Errorf("mls: multiple update and/or remove proposals apply to the same leaf")
			}
			updateOrRemove[sender] = struct{}{}
		case ProposalTypeRemove:
			if prop.remove.removed == committer {
				return fmt.Errorf("mls: remove proposal removes the committer")
			}
			if _, dup := updateOrRemove[prop.remove.removed]; dup {
				return fmt.Errorf("mls: multiple update and/or remove proposals apply to the same leaf")
			}
			updateOrRemove[prop.remove.removed] = struct{}{}
		case ProposalTypePSK:
			b, err := Marshal(&prop.preSharedKey.psk)
			if err != nil {
				return err
			}
			k := string(b)
			if _, dup := psk[k]; dup {
				return fmt.Errorf("mls: multiple PSK proposals reference the same PSK ID")
			}
			psk[k] = struct{}{}
		case ProposalTypeGroupContextExtensions:
			if groupContextExtensions {
				return fmt.Errorf("mls: multiple group context extensions proposals")
			}
			groupContextExtensions = true
		case ProposalTypeReinit:
			if len(proposals) > 1 {
				return fmt.Errorf("mls: reinit proposal together with any other proposal")
			}
		case ProposalTypeExternalInit:
			return fmt.Errorf("mls: external init proposal is not allowed")
		}
	}
	return nil
}

func ProposalListNeedsPath(proposals []Proposal) bool {
	if len(proposals) == 0 {
		return true
	}

	for _, prop := range proposals {
		switch prop.proposalType {
		case ProposalTypeUpdate, ProposalTypeRemove, ProposalTypeExternalInit, ProposalTypeGroupContextExtensions:
			return true
		}
	}

	return false
}

type GroupInfo struct {
	groupContext    GroupContext
	extensions      []Extension
	confirmationTag []byte
	signer          leafIndex
	signature       []byte
}

func (info *GroupInfo) Unmarshal(s *cryptobyte.String) error {
	*info = GroupInfo{}

	if err := info.groupContext.Unmarshal(s); err != nil {
		return err
	}

	exts, err := UnmarshalExtensionVec(s)
	if err != nil {
		return err
	}
	info.extensions = exts

	if !ReadOpaqueVec(s, &info.confirmationTag) || !s.ReadUint32((*uint32)(&info.signer)) || !ReadOpaqueVec(s, &info.signature) {
		return err
	}

	return nil
}

func (info *GroupInfo) Marshal(b *cryptobyte.Builder) {
	(*GroupInfoTBS)(info).Marshal(b)
	WriteOpaqueVec(b, info.signature)
}

func (info *GroupInfo) VerifySignature(signerPub SignaturePublicKey) bool {
	cs := info.groupContext.CipherSuite
	tbs, err := Marshal((*GroupInfoTBS)(info))
	if err != nil {
		return false
	}
	return cs.VerifyWithLabel([]byte(signerPub), []byte("GroupInfoTBS"), tbs, info.signature)
}

func (info *GroupInfo) VerifyConfirmationTag(joinerSecret, pskSecret []byte) bool {
	cs := info.groupContext.CipherSuite
	epochSecret, err := info.groupContext.ExtractEpochSecret(joinerSecret, pskSecret)
	if err != nil {
		return false
	}
	confirmationKey, err := cs.DeriveSecret(epochSecret, secretLabelConfirm)
	if err != nil {
		return false
	}
	return cs.verifyMAC(confirmationKey, info.groupContext.ConfirmedTranscriptHash, info.confirmationTag)
}

type GroupInfoTBS GroupInfo

func (info *GroupInfoTBS) Marshal(b *cryptobyte.Builder) {
	info.groupContext.Marshal(b)
	MarshalExtensionVec(b, info.extensions)
	WriteOpaqueVec(b, info.confirmationTag)
	b.AddUint32(uint32(info.signer))
}

type GroupSecrets struct {
	joinerSecret []byte
	pathSecret   []byte // optional
	psks         []PreSharedKeyID
}

func (sec *GroupSecrets) Unmarshal(s *cryptobyte.String) error {
	*sec = GroupSecrets{}

	if !ReadOpaqueVec(s, &sec.joinerSecret) {
		return io.ErrUnexpectedEOF
	}

	var hasPathSecret bool
	if !ReadOptional(s, &hasPathSecret) {
		return io.ErrUnexpectedEOF
	} else if hasPathSecret && !ReadOpaqueVec(s, &sec.pathSecret) {
		return io.ErrUnexpectedEOF
	}

	return ReadVector(s, func(s *cryptobyte.String) error {
		var psk PreSharedKeyID
		if err := psk.Unmarshal(s); err != nil {
			return err
		}
		sec.psks = append(sec.psks, psk)
		return nil
	})
}

func (sec *GroupSecrets) Marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, sec.joinerSecret)

	WriteOptional(b, sec.pathSecret != nil)
	if sec.pathSecret != nil {
		WriteOpaqueVec(b, sec.pathSecret)
	}

	WriteVector(b, len(sec.psks), func(b *cryptobyte.Builder, i int) {
		sec.psks[i].Marshal(b)
	})
}

// verifySingleReInitOrBranchPSK verifies that at most one key has type
// resumption with usage reinit or branch.
func (sec *GroupSecrets) VerifySingleReinitOrBranchPSK() bool {
	n := 0
	for _, pskID := range sec.psks {
		if pskID.pskType != pskTypeResumption {
			continue
		}
		switch pskID.usage {
		case ResumptionPSKUsageReinit, ResumptionPSKUsageBranch:
			n++
		}
	}
	return n <= 1
}

type Welcome struct {
	cipherSuite        CipherSuite
	secrets            []EncryptedGroupSecrets
	encryptedGroupInfo []byte
}

func (w *Welcome) Unmarshal(s *cryptobyte.String) error {
	*w = Welcome{}

	if !s.ReadUint16((*uint16)(&w.cipherSuite)) {
		return io.ErrUnexpectedEOF
	}

	err := ReadVector(s, func(s *cryptobyte.String) error {
		var sec EncryptedGroupSecrets
		if err := sec.Unmarshal(s); err != nil {
			return err
		}
		w.secrets = append(w.secrets, sec)
		return nil
	})
	if err != nil {
		return err
	}

	if !ReadOpaqueVec(s, &w.encryptedGroupInfo) {
		return io.ErrUnexpectedEOF
	}

	return nil
}

func (w *Welcome) Marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(w.cipherSuite))
	WriteVector(b, len(w.secrets), func(b *cryptobyte.Builder, i int) {
		w.secrets[i].Marshal(b)
	})
	WriteOpaqueVec(b, w.encryptedGroupInfo)
}

func (w *Welcome) findSecret(ref keyPackageRef) *EncryptedGroupSecrets {
	for i, sec := range w.secrets {
		if sec.newMember.Equal(ref) {
			return &w.secrets[i]
		}
	}
	return nil
}

func (w *Welcome) DecryptGroupSecrets(ref keyPackageRef, initKeyPriv []byte) (*GroupSecrets, error) {
	cs := w.cipherSuite

	sec := w.findSecret(ref)
	if sec == nil {
		return nil, fmt.Errorf("mls: encrypted group secrets not found for provided key package ref")
	}

	rawGroupSecrets, err := cs.DecryptWithLabel(initKeyPriv, []byte("Welcome"), w.encryptedGroupInfo, sec.encryptedGroupSecrets.KEMOutput, sec.encryptedGroupSecrets.Ciphertext)
	if err != nil {
		return nil, err
	}
	var groupSecrets GroupSecrets
	if err := Unmarshal(rawGroupSecrets, &groupSecrets); err != nil {
		return nil, err
	}

	return &groupSecrets, err
}

func (w *Welcome) DecryptGroupInfo(joinerSecret, pskSecret []byte) (*GroupInfo, error) {
	cs := w.cipherSuite
	_, _, aead := cs.hpke().Params()

	welcomeSecret, err := ExtractWelcomeSecret(cs, joinerSecret, pskSecret)
	if err != nil {
		return nil, err
	}

	welcomeNonce, err := cs.ExpandWithLabel(welcomeSecret, []byte("nonce"), nil, uint16(aead.NonceSize()))
	if err != nil {
		return nil, err
	}
	welcomeKey, err := cs.ExpandWithLabel(welcomeSecret, []byte("key"), nil, uint16(aead.KeySize()))
	if err != nil {
		return nil, err
	}

	welcomeCipher, err := aead.New(welcomeKey)
	if err != nil {
		return nil, err
	}
	rawGroupInfo, err := welcomeCipher.Open(nil, welcomeNonce, w.encryptedGroupInfo, nil)
	if err != nil {
		return nil, err
	}

	var groupInfo GroupInfo
	if err := Unmarshal(rawGroupInfo, &groupInfo); err != nil {
		return nil, err
	}

	return &groupInfo, nil
}

type EncryptedGroupSecrets struct {
	newMember             keyPackageRef
	encryptedGroupSecrets HPKECiphertext
}

func (sec *EncryptedGroupSecrets) Unmarshal(s *cryptobyte.String) error {
	*sec = EncryptedGroupSecrets{}
	if !ReadOpaqueVec(s, (*[]byte)(&sec.newMember)) {
		return io.ErrUnexpectedEOF
	}
	if err := sec.encryptedGroupSecrets.unmarshal(s); err != nil {
		return err
	}
	return nil
}

func (sec *EncryptedGroupSecrets) Marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, []byte(sec.newMember))
	sec.encryptedGroupSecrets.marshal(b)
}
