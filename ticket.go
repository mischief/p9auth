package p9auth

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	AuthTreq   = 1  /* ticket request */
	AuthChal   = 2  /* challenge box request */
	AuthPass   = 3  /* change password */
	AuthOK     = 4  /* fixed length reply follows */
	AuthErr    = 5  /* error follows */
	AuthMod    = 6  /* modify user */
	AuthApop   = 7  /* apop authentication for pop3 */
	AuthOKvar  = 9  /* variable length reply follows */
	AuthChap   = 10 /* chap authentication for ppp */
	AuthMSchap = 11 /* MS chap authentication for ppp */
	AuthCram   = 12 /* CRAM verification for IMAP (RFC2195 & rfc2104) */
	AuthHTTP   = 13 /* http domain login */
	AuthVNC    = 14 /* VNC server login (deprecated) */

	AuthTs = 64 /* ticket encrypted with server's key */
	AuthTc = 65 /* ticket encrypted with client's key */
	AuthAs = 66 /* server generated authenticator */
	AuthAc = 67 /* client generated authenticator */
	AuthTp = 68 /* ticket encrypted with client's key for password change */
	AuthHr = 69 /* http reply */
)

var (
	typenametab = map[int]string{
		AuthTreq: "AuthTreq",
		AuthOK:   "AuthOK",
		AuthErr:  "AuthErr",
	}
)

func btos(b []byte) string {
	if i := bytes.IndexByte(b, byte(0)); i != -1 {
		return string(b[:i])
	}
	return string(b[:])
}

type TicketReq struct {
	Type    uint8
	AuthID  [ANAMELEN]byte
	AuthDom [DOMLEN]byte
	Chal    [CHALLEN]byte
	HostID  [ANAMELEN]byte
	UID     [ANAMELEN]byte
}

func (t TicketReq) String() string {
	typ := typenametab[int(t.Type)]
	if typ == "" {
		typ = "unknown"
	}
	return typ + " " + btos(t.AuthID[:]) + "@" + btos(t.AuthDom[:]) +
		" chal " + fmt.Sprintf("%x", t.Chal[:]) +
		" hostid " + btos(t.HostID[:]) +
		" uid " + btos(t.UID[:])
}

type Ticket struct {
	Num  uint8
	Chal [CHALLEN]byte
	Cuid [ANAMELEN]byte
	Suid [ANAMELEN]byte
	Key  [DESKEYLEN]byte
}

// ToM encrypts the Ticket in a suitable format to send back to a client.
func (t *Ticket) ToM(key []byte) []byte {
	buf := new(bytes.Buffer)

	copy(t.Key[:], key[:7])
	binary.Write(buf, binary.LittleEndian, t)

	if key != nil {
		DesEncrypt(key, buf.Bytes())
	}

	if buf.Len() != TICKLEN {
		panic("bad ticket size")
	}

	return buf.Bytes()
}
