package p9auth

import (
	"testing"
)

func TestTicketToM(t *testing.T) {
	ti := Ticket{}
	ti.Num = 1
	copy(ti.Chal[:], []byte("12345678"))
	copy(ti.Cuid[:], []byte("none"))
	copy(ti.Suid[:], []byte("none"))

	m := ti.ToM(PassToKey("password"))

	if m == nil || len(m) != TICKLEN {
		t.Fatal("ticket encryption failure")
	}
}
