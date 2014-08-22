package p9auth

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
)

type AuthDb interface {
	Key(user, dom string) ([DESKEYLEN]byte, error)
}

type AuthSrv struct {
	li  net.Listener
	db  AuthDb
	log *log.Logger
}

func NewAuthSrv(listener net.Listener, db AuthDb) *AuthSrv {
	return &AuthSrv{listener, db, log.New(ioutil.Discard, "", 0)}
}

func (a *AuthSrv) Serve() error {
	for {
		c, err := a.li.Accept()
		if err != nil {
			a.log.Print(err)
			return err
		}
		a.log.Printf("accept from %s", c.RemoteAddr())
		go a.servecli(c)
	}
}

func (a *AuthSrv) SetLogger(logger *log.Logger) {
	if logger == nil {
		a.log = log.New(ioutil.Discard, "", 0)
		return
	}

	a.log = logger
}

func (a *AuthSrv) servecli(con net.Conn) {
	tr := &TicketReq{}
	err := binary.Read(con, binary.LittleEndian, tr)
	if err != nil {
		aerr(con, err)
		a.log.Print(err)
		return
	}

	// handle different types of requests here
	switch tr.Type {
	case AuthTreq:
		a.ticketrequest(con, tr)
	default:
		a.log.Printf("unhandled Ticketreq %d", tr.Type)
	}
}

func (a *AuthSrv) ticketrequest(con net.Conn, tr *TicketReq) {
	var akey, hkey [DESKEYLEN]byte
	var m []byte
	var err error
	var t Ticket

	said := btos(tr.AuthID[:])
	sdom := btos(tr.AuthDom[:])
	shid := btos(tr.HostID[:])

	if akey, err = a.db.Key(said, sdom); err != nil {
		a.log.Printf("tr-fail dom %s authid %s", sdom, said)
		goto fail
	}

	if hkey, err = a.db.Key(shid, sdom); err != nil {
		a.log.Printf("tr-fail dom %s hostid %s", sdom, shid)
		goto fail
	}

	copy(t.Chal[:], tr.Chal[:])
	copy(t.Cuid[:], tr.UID[:])

	/* speaksfor(tr.Hostid, tr.Uid) */
	copy(t.Suid[:], tr.UID[:])

	copy(t.Key[:], mkkey())

	con.Write([]byte{AuthOK})

	t.Num = AuthTc
	m = t.ToM(hkey[:])
	con.Write(m)

	t.Num = AuthTs
	m = t.ToM(akey[:])
	con.Write(m)

	a.log.Printf("tr-ok dom %s %s@%s -> %s@%s", sdom, btos(tr.UID[:]), shid, btos(tr.UID[:]), said)

	return

fail:
	aerr(con, err)
	a.log.Print(err)
	return
}

// helper for writing errors
func aerr(c net.Conn, err error) {
	c.Write([]byte{AuthErr})
	fmt.Fprintf(c, "%-64.64s", err)
}

// helper to make deskey
func mkkey() []byte {
	k := make([]byte, DESKEYLEN)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}
