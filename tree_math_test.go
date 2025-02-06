package mls

import (
	"fmt"
	"testing"
)

type treeMathTest struct {
	NLeaves NumLeaves `json:"n_leaves"`

	NNodes  uint32       `json:"n_nodes"`
	Root    NodeIndex    `json:"root"`
	Left    []*NodeIndex `json:"left"`
	Right   []*NodeIndex `json:"right"`
	Parent  []*NodeIndex `json:"parent"`
	Sibling []*NodeIndex `json:"sibling"`
}

func testTreeMath(t *testing.T, tc *treeMathTest) {
	n := tc.NLeaves
	if w := n.Width(); w != tc.NNodes {
		t.Errorf("width(%v) = %v, want %v", n, w, tc.NNodes)
	}
	if r := n.Root(); r != tc.Root {
		t.Errorf("root(%v) = %v, want %v", n, r, tc.Root)
	}
	for i, want := range tc.Left {
		x := NodeIndex(i)
		l := newOptionalNodeIndex(x.Left())
		if !optionalNodeIndexEqual(l, want) {
			t.Errorf("left(%v) = %v, want %v", x, l, want)
		}
	}
	for i, want := range tc.Right {
		x := NodeIndex(i)
		r := newOptionalNodeIndex(x.Right())
		if !optionalNodeIndexEqual(r, want) {
			t.Errorf("right(%v) = %v, want %v", x, r, want)
		}
	}
	for i, want := range tc.Parent {
		x := NodeIndex(i)
		p := newOptionalNodeIndex(n.Parent(x))
		if !optionalNodeIndexEqual(p, want) {
			t.Errorf("parent(%v) = %v, want %v", x, p, want)
		}
	}
	for i, want := range tc.Sibling {
		x := NodeIndex(i)
		s := newOptionalNodeIndex(n.Sibling(x))
		if !optionalNodeIndexEqual(s, want) {
			t.Errorf("sibling(%v) = %v, want %v", x, s, want)
		}
	}
}

func newOptionalNodeIndex(x NodeIndex, ok bool) *NodeIndex {
	if !ok {
		return nil
	}
	return &x
}

func optionalNodeIndexEqual(x, y *NodeIndex) bool {
	if x == nil || y == nil {
		return x == nil && y == nil
	}
	return *x == *y
}

func TestTreeMath(t *testing.T) {
	var tests []treeMathTest
	loadTestVector(t, "testdata/tree-math.json", &tests)

	for _, tc := range tests {
		t.Run(fmt.Sprintf("numLeaves(%v)", tc.NLeaves), func(t *testing.T) {
			testTreeMath(t, &tc)
		})
	}
}
