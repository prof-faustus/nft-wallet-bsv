package bsvscript

import "testing"

func TestHasOpReturn(t *testing.T) {
	cases := []struct {
		name   string
		script []byte
		want   bool
	}{
		{"empty", nil, false},
		{"bare OP_RETURN", []byte{0x6a}, true},
		{"OP_RETURN with push", []byte{0x6a, 0x02, 0xde, 0xad}, true},
		{"P2PKH, no 0x6a", []byte{0x76, 0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x88, 0xac}, false},
		// P2PKH whose 20-byte hash CONTAINS 0x6a as a data byte — must NOT match.
		{"P2PKH with 0x6a in hash", []byte{0x76, 0xa9, 0x14, 0x6a, 0x6a, 0x6a, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x88, 0xac}, false},
		// A push of 0x6a bytes, then a normal opcode — the pushed 0x6a is data.
		{"pushed 0x6a data only", []byte{0x03, 0x6a, 0x6a, 0x6a, 0xac}, false},
		// OP_RETURN AFTER a push that itself contains 0x6a — must match.
		{"push then real OP_RETURN", []byte{0x02, 0x6a, 0x6a, 0x6a}, true},
	}
	for _, c := range cases {
		if got := HasOpReturn(c.script); got != c.want {
			t.Errorf("%s: HasOpReturn=%v want %v", c.name, got, c.want)
		}
	}
}
