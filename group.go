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
	ProposalType           ProposalType
	Add                    *Add                    // for proposalTypeAdd
	Update                 *Update                 // for proposalTypeUpdate
	Remove                 *Remove                 // for proposalTypeRemove
	PreSharedKey           *PreSharedKey           // for proposalTypePSK
	ReInit                 *ReInit                 // for proposalTypeReinit
	ExternalInit           *ExternalInit           // for proposalTypeExternalInit
	GroupContextExtensions *GroupContextExtensions // for proposalTypeGroupContextExtensions
}

func (prop *Proposal) Unmarshal(s *cryptobyte.String) error {
	*prop = Proposal{}
	if err := prop.ProposalType.Unmarshal(s); err != nil {
		return err
	}
	switch prop.ProposalType {
	case ProposalTypeAdd:
		prop.Add = new(Add)
		return prop.Add.Unmarshal(s)
	case ProposalTypeUpdate:
		prop.Update = new(Update)
		return prop.Update.Unmarshal(s)
	case ProposalTypeRemove:
		prop.Remove = new(Remove)
		return prop.Remove.Unmarshal(s)
	case ProposalTypePSK:
		prop.PreSharedKey = new(PreSharedKey)
		return prop.PreSharedKey.Unmarshal(s)
	case ProposalTypeReinit:
		prop.ReInit = new(ReInit)
		return prop.ReInit.Unmarshal(s)
	case ProposalTypeExternalInit:
		prop.ExternalInit = new(ExternalInit)
		return prop.ExternalInit.Unmarshal(s)
	case ProposalTypeGroupContextExtensions:
		prop.GroupContextExtensions = new(GroupContextExtensions)
		return prop.GroupContextExtensions.Unmarshal(s)
	default:
		panic("unreachable")
	}
}

func (prop *Proposal) Marshal(b *cryptobyte.Builder) {
	prop.ProposalType.Marshal(b)
	switch prop.ProposalType {
	case ProposalTypeAdd:
		prop.Add.Marshal(b)
	case ProposalTypeUpdate:
		prop.Update.Marshal(b)
	case ProposalTypeRemove:
		prop.Remove.Marshal(b)
	case ProposalTypePSK:
		prop.PreSharedKey.Marshal(b)
	case ProposalTypeReinit:
		prop.ReInit.Marshal(b)
	case ProposalTypeExternalInit:
		prop.ExternalInit.Marshal(b)
	case ProposalTypeGroupContextExtensions:
		prop.GroupContextExtensions.Marshal(b)
	default:
		panic("unreachable")
	}
}

type Add struct {
	KeyPackage KeyPackage
}

func (a *Add) Unmarshal(s *cryptobyte.String) error {
	*a = Add{}
	return a.KeyPackage.Unmarshal(s)
}

func (a *Add) Marshal(b *cryptobyte.Builder) {
	a.KeyPackage.Marshal(b)
}

type Update struct {
	LeafNode LeafNode
}

func (upd *Update) Unmarshal(s *cryptobyte.String) error {
	*upd = Update{}
	return upd.LeafNode.Unmarshal(s)
}

func (upd *Update) Marshal(b *cryptobyte.Builder) {
	upd.LeafNode.Marshal(b)
}

type Remove struct {
	Removed LeafIndex
}

func (rm *Remove) Unmarshal(s *cryptobyte.String) error {
	*rm = Remove{}
	if !s.ReadUint32((*uint32)(&rm.Removed)) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (rm *Remove) Marshal(b *cryptobyte.Builder) {
	b.AddUint32(uint32(rm.Removed))
}

type PreSharedKey struct {
	PSK PreSharedKeyID
}

func (psk *PreSharedKey) Unmarshal(s *cryptobyte.String) error {
	*psk = PreSharedKey{}
	return psk.PSK.Unmarshal(s)
}

func (psk *PreSharedKey) Marshal(b *cryptobyte.Builder) {
	psk.PSK.Marshal(b)
}

type ReInit struct {
	GroupID     GroupID
	Version     ProtocolVersion
	CipherSuite CipherSuite
	Extensions  []Extension
}

func (ri *ReInit) Unmarshal(s *cryptobyte.String) error {
	*ri = ReInit{}

	if !ReadOpaqueVec(s, (*[]byte)(&ri.GroupID)) || !s.ReadUint16((*uint16)(&ri.Version)) || !s.ReadUint16((*uint16)(&ri.CipherSuite)) {
		return io.ErrUnexpectedEOF
	}

	exts, err := UnmarshalExtensionVec(s)
	if err != nil {
		return err
	}
	ri.Extensions = exts

	return nil
}

func (ri *ReInit) Marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, []byte(ri.GroupID))
	b.AddUint16(uint16(ri.Version))
	b.AddUint16(uint16(ri.CipherSuite))
	MarshalExtensionVec(b, ri.Extensions)
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
	Extensions []Extension
}

func (exts *GroupContextExtensions) Unmarshal(s *cryptobyte.String) error {
	*exts = GroupContextExtensions{}

	l, err := UnmarshalExtensionVec(s)
	if err != nil {
		return err
	}
	exts.Extensions = l

	return nil
}

func (exts *GroupContextExtensions) Marshal(b *cryptobyte.Builder) {
	MarshalExtensionVec(b, exts.Extensions)
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
	Type      ProposalOrRefType
	Proposal  *Proposal   // for proposalOrRefTypeProposal
	Reference ProposalRef // for proposalOrRefTypeReference
}

func (propOrRef *ProposalOrRef) Unmarshal(s *cryptobyte.String) error {
	*propOrRef = ProposalOrRef{}

	if err := propOrRef.Type.Unmarshal(s); err != nil {
		return err
	}

	switch propOrRef.Type {
	case ProposalOrRefTypeProposal:
		propOrRef.Proposal = new(Proposal)
		return propOrRef.Proposal.Unmarshal(s)
	case ProposalOrRefTypeReference:
		if !ReadOpaqueVec(s, (*[]byte)(&propOrRef.Reference)) {
			return io.ErrUnexpectedEOF
		}
		return nil
	default:
		panic("unreachable")
	}
}

func (propOrRef *ProposalOrRef) Marshal(b *cryptobyte.Builder) {
	propOrRef.Type.Marshal(b)
	switch propOrRef.Type {
	case ProposalOrRefTypeProposal:
		propOrRef.Proposal.Marshal(b)
	case ProposalOrRefTypeReference:
		WriteOpaqueVec(b, []byte(propOrRef.Reference))
	default:
		panic("unreachable")
	}
}

type Commit struct {
	Proposals []ProposalOrRef
	Path      *UpdatePath // optional
}

func (c *Commit) Unmarshal(s *cryptobyte.String) error {
	*c = Commit{}

	err := ReadVector(s, func(s *cryptobyte.String) error {
		var propOrRef ProposalOrRef
		if err := propOrRef.Unmarshal(s); err != nil {
			return err
		}
		c.Proposals = append(c.Proposals, propOrRef)
		return nil
	})
	if err != nil {
		return err
	}

	var hasPath bool
	if !ReadOptional(s, &hasPath) {
		return io.ErrUnexpectedEOF
	} else if hasPath {
		c.Path = new(UpdatePath)
		if err := c.Path.Unmarshal(s); err != nil {
			return err
		}
	}

	return nil
}

func (c *Commit) Marshal(b *cryptobyte.Builder) {
	WriteVector(b, len(c.Proposals), func(b *cryptobyte.Builder, i int) {
		c.Proposals[i].Marshal(b)
	})
	WriteOptional(b, c.Path != nil)
	if c.Path != nil {
		c.Path.Marshal(b)
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
func VerifyProposalList(proposals []Proposal, senders []LeafIndex, committer LeafIndex) error {
	if len(proposals) != len(senders) {
		panic("unreachable")
	}

	add := make(map[string]struct{})
	updateOrRemove := make(map[LeafIndex]struct{})
	psk := make(map[string]struct{})
	groupContextExtensions := false
	for i, prop := range proposals {
		sender := senders[i]

		switch prop.ProposalType {
		case ProposalTypeAdd:
			k := string(prop.Add.KeyPackage.LeafNode.SignatureKey)
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
			if prop.Remove.Removed == committer {
				return fmt.Errorf("mls: remove proposal removes the committer")
			}
			if _, dup := updateOrRemove[prop.Remove.Removed]; dup {
				return fmt.Errorf("mls: multiple update and/or remove proposals apply to the same leaf")
			}
			updateOrRemove[prop.Remove.Removed] = struct{}{}
		case ProposalTypePSK:
			b, err := Marshal(&prop.PreSharedKey.PSK)
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
		switch prop.ProposalType {
		case ProposalTypeUpdate, ProposalTypeRemove, ProposalTypeExternalInit, ProposalTypeGroupContextExtensions:
			return true
		}
	}

	return false
}

type GroupInfo struct {
	GroupContext    GroupContext
	Extensions      []Extension
	ConfirmationTag []byte
	Signer          LeafIndex
	Signature       []byte
}

func (info *GroupInfo) Unmarshal(s *cryptobyte.String) error {
	*info = GroupInfo{}

	if err := info.GroupContext.Unmarshal(s); err != nil {
		return err
	}

	exts, err := UnmarshalExtensionVec(s)
	if err != nil {
		return err
	}
	info.Extensions = exts

	if !ReadOpaqueVec(s, &info.ConfirmationTag) || !s.ReadUint32((*uint32)(&info.Signer)) || !ReadOpaqueVec(s, &info.Signature) {
		return err
	}

	return nil
}

func (info *GroupInfo) Marshal(b *cryptobyte.Builder) {
	(*GroupInfoTBS)(info).Marshal(b)
	WriteOpaqueVec(b, info.Signature)
}

func (info *GroupInfo) VerifySignature(signerPub SignaturePublicKey) bool {
	cs := info.GroupContext.CipherSuite
	tbs, err := Marshal((*GroupInfoTBS)(info))
	if err != nil {
		return false
	}
	return cs.VerifyWithLabel([]byte(signerPub), []byte("GroupInfoTBS"), tbs, info.Signature)
}

func (info *GroupInfo) VerifyConfirmationTag(joinerSecret, pskSecret []byte) bool {
	cs := info.GroupContext.CipherSuite
	epochSecret, err := info.GroupContext.ExtractEpochSecret(joinerSecret, pskSecret)
	if err != nil {
		return false
	}
	confirmationKey, err := cs.DeriveSecret(epochSecret, SecretLabelConfirm)
	if err != nil {
		return false
	}
	return cs.VerifyMAC(confirmationKey, info.GroupContext.ConfirmedTranscriptHash, info.ConfirmationTag)
}

type GroupInfoTBS GroupInfo

func (info *GroupInfoTBS) Marshal(b *cryptobyte.Builder) {
	info.GroupContext.Marshal(b)
	MarshalExtensionVec(b, info.Extensions)
	WriteOpaqueVec(b, info.ConfirmationTag)
	b.AddUint32(uint32(info.Signer))
}

type GroupSecrets struct {
	JoinerSecret []byte
	PathSecret   []byte // optional
	PSKs         []PreSharedKeyID
}

func (sec *GroupSecrets) Unmarshal(s *cryptobyte.String) error {
	*sec = GroupSecrets{}

	if !ReadOpaqueVec(s, &sec.JoinerSecret) {
		return io.ErrUnexpectedEOF
	}

	var hasPathSecret bool
	if !ReadOptional(s, &hasPathSecret) {
		return io.ErrUnexpectedEOF
	} else if hasPathSecret && !ReadOpaqueVec(s, &sec.PathSecret) {
		return io.ErrUnexpectedEOF
	}

	return ReadVector(s, func(s *cryptobyte.String) error {
		var psk PreSharedKeyID
		if err := psk.Unmarshal(s); err != nil {
			return err
		}
		sec.PSKs = append(sec.PSKs, psk)
		return nil
	})
}

func (sec *GroupSecrets) Marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, sec.JoinerSecret)

	WriteOptional(b, sec.PathSecret != nil)
	if sec.PathSecret != nil {
		WriteOpaqueVec(b, sec.PathSecret)
	}

	WriteVector(b, len(sec.PSKs), func(b *cryptobyte.Builder, i int) {
		sec.PSKs[i].Marshal(b)
	})
}

// verifySingleReInitOrBranchPSK verifies that at most one key has type
// resumption with usage reinit or branch.
func (sec *GroupSecrets) VerifySingleReinitOrBranchPSK() bool {
	n := 0
	for _, pskID := range sec.PSKs {
		if pskID.PSKType != PSKTypeResumption {
			continue
		}
		switch pskID.Usage {
		case ResumptionPSKUsageReinit, ResumptionPSKUsageBranch:
			n++
		}
	}
	return n <= 1
}

type Welcome struct {
	CipherSuite        CipherSuite
	Secrets            []EncryptedGroupSecrets
	EncryptedGroupInfo []byte
}

func (w *Welcome) Unmarshal(s *cryptobyte.String) error {
	*w = Welcome{}

	if !s.ReadUint16((*uint16)(&w.CipherSuite)) {
		return io.ErrUnexpectedEOF
	}

	err := ReadVector(s, func(s *cryptobyte.String) error {
		var sec EncryptedGroupSecrets
		if err := sec.Unmarshal(s); err != nil {
			return err
		}
		w.Secrets = append(w.Secrets, sec)
		return nil
	})
	if err != nil {
		return err
	}

	if !ReadOpaqueVec(s, &w.EncryptedGroupInfo) {
		return io.ErrUnexpectedEOF
	}

	return nil
}

func (w *Welcome) Marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(w.CipherSuite))
	WriteVector(b, len(w.Secrets), func(b *cryptobyte.Builder, i int) {
		w.Secrets[i].Marshal(b)
	})
	WriteOpaqueVec(b, w.EncryptedGroupInfo)
}

func (w *Welcome) FindSecret(ref KeyPackageRef) *EncryptedGroupSecrets {
	for i, sec := range w.Secrets {
		if sec.NewMember.Equal(ref) {
			return &w.Secrets[i]
		}
	}
	return nil
}

func (w *Welcome) DecryptGroupSecrets(ref KeyPackageRef, initKeyPriv []byte) (*GroupSecrets, error) {
	cs := w.CipherSuite

	sec := w.FindSecret(ref)
	if sec == nil {
		return nil, fmt.Errorf("mls: encrypted group secrets not found for provided key package ref")
	}

	rawGroupSecrets, err := cs.DecryptWithLabel(initKeyPriv, []byte("Welcome"), w.EncryptedGroupInfo, sec.EncryptedGroupSecrets.KEMOutput, sec.EncryptedGroupSecrets.Ciphertext)
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
	cs := w.CipherSuite
	_, _, aead := cs.HPKE().Params()

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
	rawGroupInfo, err := welcomeCipher.Open(nil, welcomeNonce, w.EncryptedGroupInfo, nil)
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
	NewMember             KeyPackageRef
	EncryptedGroupSecrets HPKECiphertext
}

func (sec *EncryptedGroupSecrets) Unmarshal(s *cryptobyte.String) error {
	*sec = EncryptedGroupSecrets{}
	if !ReadOpaqueVec(s, (*[]byte)(&sec.NewMember)) {
		return io.ErrUnexpectedEOF
	}
	if err := sec.EncryptedGroupSecrets.unmarshal(s); err != nil {
		return err
	}
	return nil
}

func (sec *EncryptedGroupSecrets) Marshal(b *cryptobyte.Builder) {
	WriteOpaqueVec(b, []byte(sec.NewMember))
	sec.EncryptedGroupSecrets.marshal(b)
}
