package mls

import (
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

type GroupContext struct {
	Version                 ProtocolVersion
	CipherSuite             CipherSuite
	GroupID                 GroupID
	Epoch                   uint64
	TreeHash                []byte
	ConfirmedTranscriptHash []byte
	Extensions              []Extension
}

func (ctx *GroupContext) Unmarshal(s *cryptobyte.String) error {
	*ctx = GroupContext{}

	ok := s.ReadUint16((*uint16)(&ctx.Version)) &&
		s.ReadUint16((*uint16)(&ctx.CipherSuite)) &&
		ReadOpaqueVec(s, (*[]byte)(&ctx.GroupID)) &&
		s.ReadUint64(&ctx.Epoch) &&
		ReadOpaqueVec(s, &ctx.TreeHash) &&
		ReadOpaqueVec(s, &ctx.ConfirmedTranscriptHash)
	if !ok {
		return io.ErrUnexpectedEOF
	}

	if ctx.Version != ProtocolVersionMLS10 {
		return fmt.Errorf("mls: invalid protocol version %d", ctx.Version)
	}

	exts, err := UnmarshalExtensionVec(s)
	if err != nil {
		return err
	}
	ctx.Extensions = exts

	return nil
}

func (ctx *GroupContext) Marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(ctx.Version))
	b.AddUint16(uint16(ctx.CipherSuite))
	WriteOpaqueVec(b, []byte(ctx.GroupID))
	b.AddUint64(ctx.Epoch)
	WriteOpaqueVec(b, ctx.TreeHash)
	WriteOpaqueVec(b, ctx.ConfirmedTranscriptHash)
	MarshalExtensionVec(b, ctx.Extensions)
}

func (ctx *GroupContext) ExtractJoinerSecret(prevInitSecret, commitSecret []byte) ([]byte, error) {
	cs := ctx.CipherSuite
	_, kdf, _ := cs.HPKE().Params()

	extracted := kdf.Extract(commitSecret, prevInitSecret)

	rawGroupContext, err := Marshal(ctx)
	if err != nil {
		return nil, err
	}
	return cs.ExpandWithLabel(extracted, []byte("joiner"), rawGroupContext, uint16(kdf.ExtractSize()))
}

func (ctx *GroupContext) ExtractEpochSecret(joinerSecret, pskSecret []byte) ([]byte, error) {
	cs := ctx.CipherSuite
	_, kdf, _ := cs.HPKE().Params()

	// TODO de-duplicate with extractWelcomeSecret
	if pskSecret == nil {
		pskSecret = make([]byte, kdf.ExtractSize())
	}
	extracted := kdf.Extract(pskSecret, joinerSecret)

	rawGroupContext, err := Marshal(ctx)
	if err != nil {
		return nil, err
	}
	return cs.ExpandWithLabel(extracted, []byte("epoch"), rawGroupContext, uint16(kdf.ExtractSize()))
}

func ExtractWelcomeSecret(cs CipherSuite, joinerSecret, pskSecret []byte) ([]byte, error) {
	_, kdf, _ := cs.HPKE().Params()

	if pskSecret == nil {
		pskSecret = make([]byte, kdf.ExtractSize())
	}
	extracted := kdf.Extract(pskSecret, joinerSecret)

	return cs.DeriveSecret(extracted, []byte("welcome"))
}

func DeriveExporter(cs CipherSuite, exporterSecret, label, context []byte, length uint16) ([]byte, error) {
	derived, err := cs.DeriveSecret(exporterSecret, label)
	if err != nil {
		return nil, err
	}

	h := cs.hash().New()
	h.Write(context)

	return cs.ExpandWithLabel(derived, []byte("exported"), h.Sum(nil), length)
}

var (
	SecretLabelInit           = []byte("init")
	SecretLabelSenderData     = []byte("sender data")
	SecretLabelEncryption     = []byte("encryption")
	SecretLabelExporter       = []byte("exporter")
	SecretLabelExternal       = []byte("external")
	SecretLabelConfirm        = []byte("confirm")
	SecretLabelMembership     = []byte("membership")
	SecretLabelResumption     = []byte("resumption")
	SecretLabelAuthentication = []byte("authentication")
)

type ConfirmedTranscriptHashInput struct {
	WireFormat WireFormat
	Content    FramedContent
	Signature  []byte
}

func (input *ConfirmedTranscriptHashInput) Marshal(b *cryptobyte.Builder) {
	if input.Content.ContentType != contentTypeCommit {
		b.SetError(fmt.Errorf("mls: confirmedTranscriptHashInput can only contain contentTypeCommit"))
		return
	}
	input.WireFormat.Marshal(b)
	input.Content.marshal(b)
	WriteOpaqueVec(b, input.Signature)
}

func (input *ConfirmedTranscriptHashInput) hash(cs CipherSuite, interimTranscriptHashBefore []byte) ([]byte, error) {
	rawInput, err := Marshal(input)
	if err != nil {
		return nil, err
	}

	h := cs.hash().New()
	h.Write(interimTranscriptHashBefore)
	h.Write(rawInput)
	return h.Sum(nil), nil
}

func NextInterimTranscriptHash(cs CipherSuite, confirmedTranscriptHash, confirmationTag []byte) ([]byte, error) {
	var b cryptobyte.Builder
	WriteOpaqueVec(&b, confirmationTag)
	rawInput, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	h := cs.hash().New()
	h.Write(confirmedTranscriptHash)
	h.Write(rawInput)
	return h.Sum(nil), nil
}

type PSKType uint8

const (
	PSKTypeExternal   PSKType = 1
	PSKTypeResumption PSKType = 2
)

func (t *PSKType) Unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint8((*uint8)(t)) {
		return io.ErrUnexpectedEOF
	}
	switch *t {
	case PSKTypeExternal, PSKTypeResumption:
		return nil
	default:
		return fmt.Errorf("mls: invalid PSK type %d", *t)
	}
}

func (t PSKType) Marshal(b *cryptobyte.Builder) {
	b.AddUint8(uint8(t))
}

type ResumptionPSKUsage uint8

const (
	ResumptionPSKUsageApplication ResumptionPSKUsage = 1
	ResumptionPSKUsageReinit      ResumptionPSKUsage = 2
	ResumptionPSKUsageBranch      ResumptionPSKUsage = 3
)

func (usage *ResumptionPSKUsage) Unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint8((*uint8)(usage)) {
		return io.ErrUnexpectedEOF
	}
	switch *usage {
	case ResumptionPSKUsageApplication, ResumptionPSKUsageReinit, ResumptionPSKUsageBranch:
		return nil
	default:
		return fmt.Errorf("mls: invalid resumption PSK usage %d", *usage)
	}
}

func (usage ResumptionPSKUsage) Marshal(b *cryptobyte.Builder) {
	b.AddUint8(uint8(usage))
}

type PreSharedKeyID struct {
	PSKType PSKType

	// for pskTypeExternal
	PSKID []byte

	// for pskTypeResumption
	Usage      ResumptionPSKUsage
	PSKGroupID GroupID
	PSKEpoch   uint64

	PSKNonce []byte
}

func (id *PreSharedKeyID) Unmarshal(s *cryptobyte.String) error {
	*id = PreSharedKeyID{}

	if err := id.PSKType.Unmarshal(s); err != nil {
		return err
	}

	switch id.PSKType {
	case PSKTypeExternal:
		if !ReadOpaqueVec(s, &id.PSKID) {
			return io.ErrUnexpectedEOF
		}
	case PSKTypeResumption:
		if err := id.Usage.Unmarshal(s); err != nil {
			return err
		}
		if !ReadOpaqueVec(s, (*[]byte)(&id.PSKGroupID)) || !s.ReadUint64(&id.PSKEpoch) {
			return io.ErrUnexpectedEOF
		}
	default:
		panic("unreachable")
	}

	if !ReadOpaqueVec(s, &id.PSKNonce) {
		return io.ErrUnexpectedEOF
	}

	return nil
}

func (id *PreSharedKeyID) Marshal(b *cryptobyte.Builder) {
	id.PSKType.Marshal(b)
	switch id.PSKType {
	case PSKTypeExternal:
		WriteOpaqueVec(b, id.PSKID)
	case PSKTypeResumption:
		id.Usage.Marshal(b)
		WriteOpaqueVec(b, []byte(id.PSKGroupID))
		b.AddUint64(id.PSKEpoch)
	default:
		panic("unreachable")
	}
	WriteOpaqueVec(b, id.PSKNonce)
}

func ExtractPSKSecret(cs CipherSuite, pskIDs []PreSharedKeyID, psks [][]byte) ([]byte, error) {
	if len(pskIDs) != len(psks) {
		return nil, fmt.Errorf("mls: got %v PSK IDs and %v PSKs, want same number", len(pskIDs), len(psks))
	}

	_, kdf, _ := cs.HPKE().Params()
	zero := make([]byte, kdf.ExtractSize())

	pskSecret := zero
	for i := range pskIDs {
		pskExtracted := kdf.Extract(psks[i], zero)

		pskLabel := PSKLabel{
			ID:    pskIDs[i],
			Index: uint16(i),
			Count: uint16(len(pskIDs)),
		}
		rawPSKLabel, err := Marshal(&pskLabel)
		if err != nil {
			return nil, err
		}

		pskInput, err := cs.ExpandWithLabel(pskExtracted, []byte("derived psk"), rawPSKLabel, uint16(kdf.ExtractSize()))
		if err != nil {
			return nil, err
		}

		pskSecret = kdf.Extract(pskSecret, pskInput)
	}

	return pskSecret, nil
}

type PSKLabel struct {
	ID    PreSharedKeyID
	Index uint16
	Count uint16
}

func (label *PSKLabel) Marshal(b *cryptobyte.Builder) {
	label.ID.Marshal(b)
	b.AddUint16(label.Index)
	b.AddUint16(label.Count)
}
