package mls

import (
	"bytes"
	"fmt"
	"testing"
)

func testMessages(t *testing.T, tc map[string]testBytes) {
	msgs := []struct {
		name string
		v    interface {
			Unmarshaler
			Marshaler
		}
	}{
		{"mls_welcome", new(MLSMessage)},
		{"mls_group_info", new(MLSMessage)},
		{"mls_key_package", new(MLSMessage)},

		{"ratchet_tree", new(RatchetTree)},
		{"group_secrets", new(GroupSecrets)},

		{"add_proposal", new(Add)},
		{"update_proposal", new(Update)},
		{"remove_proposal", new(Remove)},
		{"pre_shared_key_proposal", new(PreSharedKey)},
		{"re_init_proposal", new(ReInit)},
		{"external_init_proposal", new(ExternalInit)},
		{"group_context_extensions_proposal", new(GroupContextExtensions)},

		{"commit", new(Commit)},

		{"public_message_application", new(MLSMessage)},
		{"public_message_proposal", new(MLSMessage)},
		{"public_message_commit", new(MLSMessage)},
		{"private_message", new(MLSMessage)},
	}
	for _, msg := range msgs {
		t.Run(msg.name, func(t *testing.T) {
			raw, ok := tc[msg.name]
			if !ok {
				t.Fatal("reference blob not found")
			}
			if err := Unmarshal(raw, msg.v); err != nil {
				t.Fatalf("unmarshal() = %v", err)
			}

			out, err := Marshal(msg.v)
			if err != nil {
				t.Errorf("marshal() = %v", err)
			} else if !bytes.Equal(out, raw) {
				t.Errorf("marshal() = \n%v\nbut want \n%v", out, raw)
			}
		})
	}
}

func TestMessages(t *testing.T) {
	var tests []map[string]testBytes
	loadTestVector(t, "testdata/messages.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testMessages(t, tc)
		})
	}
}
