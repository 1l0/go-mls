package mls

// This package uses an array-based representation of complete balanced binary
// trees, as described in appendix C. For example, a tree with 8 leaves:
//
//                               X
//                               |
//                     .---------+---------.
//                    /                     \
//                   X                       X
//                   |                       |
//               .---+---.               .---+---.
//              /         \             /         \
//             X           X           X           X
//            / \         / \         / \         / \
//           /   \       /   \       /   \       /   \
//          X     X     X     X     X     X     X     X
//
//    Node: 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14
//
//    Leaf: 0     1     2     3     4     5     6     7

// NumLeaves exposes operations on a tree with a given number of leaves.
type NumLeaves uint32

func NumLeavesFromWidth(w uint32) NumLeaves {
	if w == 0 {
		return 0
	}
	return NumLeaves((w-1)/2 + 1)
}

// Width computes the minimum length of the array, ie. the number of nodes.
func (n NumLeaves) Width() uint32 {
	if n == 0 {
		return 0
	}
	return 2*(uint32(n)-1) + 1
}

// Root returns the index of the Root node.
func (n NumLeaves) Root() NodeIndex {
	return NodeIndex((1 << Log2(n.Width())) - 1)
}

// Parent returns the index of the Parent node for a non-root node index.
func (n NumLeaves) Parent(x NodeIndex) (NodeIndex, bool) {
	if x == n.Root() {
		return 0, false
	}
	lvl := NodeIndex(x.Level())
	b := (x >> (lvl + 1)) & 1
	p := (x | (1 << lvl)) ^ (b << (lvl + 1))
	return p, true
}

// Sibling returns the index of the other child of the node's parent.
func (n NumLeaves) Sibling(x NodeIndex) (NodeIndex, bool) {
	p, ok := n.Parent(x)
	if !ok {
		return 0, false
	}
	if x < p {
		return p.Right()
	} else {
		return p.Left()
	}
}

// DirectPath computes the direct path of a node, ordered from leaf to root.
func (n NumLeaves) DirectPath(x NodeIndex) []NodeIndex {
	var path []NodeIndex
	for {
		p, ok := n.Parent(x)
		if !ok {
			break
		}
		path = append(path, p)
		x = p
	}
	return path
}

// Copath computes the Copath of a node, ordered from leaf to root.
func (n NumLeaves) Copath(x NodeIndex) []NodeIndex {
	path := n.DirectPath(x)
	if len(path) == 0 {
		return nil
	}
	path = append([]NodeIndex{x}, path...)
	path = path[:len(path)-1]

	var copath []NodeIndex
	for _, y := range path {
		s, ok := n.Sibling(y)
		if !ok {
			panic("unreachable")
		}
		copath = append(copath, s)
	}

	return copath
}

// NodeIndex is the index of a node in a tree.
type NodeIndex uint32

// IsLeaf returns true if this is a leaf node, false if this is an intermediate
// node.
func (x NodeIndex) IsLeaf() bool {
	return x%2 == 0
}

// LeafIndex returns the index of the leaf from a node index.
func (x NodeIndex) LeafIndex() (leafIndex, bool) {
	if !x.IsLeaf() {
		return 0, false
	}
	return leafIndex(x) >> 1, true
}

// Left returns the index of the Left child for an intermediate node index.
func (x NodeIndex) Left() (NodeIndex, bool) {
	lvl := x.Level()
	if lvl == 0 {
		return 0, false
	}
	l := x ^ (1 << (NodeIndex(lvl) - 1))
	return l, true
}

// Right returns the index of the Right child for an intermediate node index.
func (x NodeIndex) Right() (NodeIndex, bool) {
	lvl := x.Level()
	if lvl == 0 {
		return 0, false
	}
	r := x ^ (3 << (NodeIndex(lvl) - 1))
	return r, true
}

// Children returns the indices of the left and right Children for an
// intermediate node index.
func (x NodeIndex) Children() (left, right NodeIndex, ok bool) {
	l, ok := x.Left()
	if !ok {
		return 0, 0, false
	}
	r, _ := x.Right()
	return l, r, true
}

// Level returns the Level of a node in the tree. Leaves are at Level 0, their
// parents are at Level 1, etc.
func (x NodeIndex) Level() uint32 {
	if x&1 == 0 {
		return 0
	}
	lvl := uint32(0)
	for (x>>lvl)&1 == 1 {
		lvl++
	}
	return lvl
}

// CommonAncestor returns the the lowest node that is in the direct paths of
// both leaves.
func CommonAncestor(x, y NodeIndex) NodeIndex {
	// Handle cases where one is an ancestor of the other
	lx, ly := x.Level()+1, y.Level()+1
	if lx <= ly && x>>ly == y>>ly {
		return y
	} else if ly <= lx && x>>lx == y>>lx {
		return x
	}

	// Handle other cases
	xn, yn := x, y
	k := 0
	for xn != yn {
		xn, yn = xn>>1, yn>>1
		k++
	}
	return (xn << k) + (1 << (k - 1)) - 1
}

type leafIndex uint32

// NodeIndex returns the index of the node from a leaf index.
func (li leafIndex) NodeIndex() NodeIndex {
	return NodeIndex(2 * li)
}

// Log2 computes the exponent of the largest power of 2 less than x.
func Log2(x uint32) uint32 {
	if x == 0 {
		return 0
	}

	k := uint32(0)
	for x>>k > 0 {
		k++
	}
	return k - 1
}

func isPowerOf2(x uint32) bool {
	return x != 0 && x&(x-1) == 0
}
