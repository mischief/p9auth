package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"net"

	"github.com/mischief/p9auth"

	"code.google.com/p/go9p/p"
	"code.google.com/p/go9p/p/clnt"

	"github.com/golang/glog"
)

type FakeUser string

func (u *FakeUser) Name() string            { return string(*u) }
func (u *FakeUser) Id() int                 { return 61508 }
func (u *FakeUser) Groups() []p.Group       { return []p.Group{u} }
func (u *FakeUser) IsMember(g p.Group) bool { return true }
func (u *FakeUser) Members() []p.User       { return []p.User{u} }

var (
	myuser  = FakeUser("auth")
	keyaddr = flag.String("k", "127.0.0.1:61509", "key server")
)

func mkkey() []byte {
	k := make([]byte, p9auth.DESKEYLEN)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}

func btos(b []byte) string {
	if i := bytes.IndexByte(b, byte(0)); i != -1 {
		return string(b[:i])
	}
	return string(b[:])
}

func findkey(cl *clnt.Clnt, user string) ([]byte, error) {
	f, err := cl.FOpen(fmt.Sprintf("%s/key", user), p.OREAD)
	if err != nil {
		return nil, fmt.Errorf("findkey: %s", err)
	}
	defer f.Close()

	ret := make([]byte, p9auth.DESKEYLEN)
	if n, err := f.ReadAt(ret, 0); n != p9auth.DESKEYLEN {
		return nil, fmt.Errorf("findkey: short key: %d", n)
	} else if err != nil {
		return nil, fmt.Errorf("findkey: %s", err)
	}

	return ret, nil
}

type authcli struct {
	con net.Conn
	p9  *clnt.Clnt
}

func (a *authcli) terr(err error) {
	a.con.Write([]byte{p9auth.AuthErr})
	fmt.Fprintf(a.con, "%64.64s", err)
}

func (a *authcli) serve() {
	defer a.con.Close()

	p9, err := clnt.Mount("tcp", *keyaddr, "", &myuser)
	if err != nil {
		a.terr(err)
		glog.Error(err)
		return
	}

	a.p9 = p9

	defer a.p9.Unmount()

	tr := &p9auth.TicketReq{}
	err = binary.Read(a.con, binary.LittleEndian, tr)
	if err != nil {
		a.terr(err)
		glog.Errorf("tr-fail %s", err)
		return
	}

	glog.Infof("tr %s", tr)

	switch tr.Type {
	case p9auth.AuthTreq:
		a.ticketrequest(tr)
	default:
		glog.Errorf("unhandled Ticketreq %d", tr.Type)
	}
}

func (a *authcli) ticketrequest(tr *p9auth.TicketReq) {
	var akey, hkey, m []byte
	var err error
	var t p9auth.Ticket

	if akey, err = findkey(a.p9, btos(tr.AuthID[:])); err != nil {
		goto fail
	}

	if hkey, err = findkey(a.p9, btos(tr.HostID[:])); err != nil {
		goto fail
	}

	copy(t.Chal[:], tr.Chal[:])
	copy(t.Cuid[:], tr.UID[:])

	/* speaksfor(tr.Hostid, tr.Uid) */
	copy(t.Suid[:], tr.UID[:])

	copy(t.Key[:], mkkey())

	a.con.Write([]byte{p9auth.AuthOK})

	t.Num = p9auth.AuthTc
	m = t.ToM(hkey)
	a.con.Write(m)

	t.Num = p9auth.AuthTs
	m = t.ToM(akey)
	a.con.Write(m)

	return

fail:
	glog.Error(err)
	a.terr(err)
	return
}

func main() {
	flag.Parse()

	//listener, err := net.Listen("tcp", ":61510")
	listener, err := net.Listen("tcp", ":567")
	if err != nil {
		glog.Error(err)
		return
	}

	for {
		c, err := listener.Accept()
		if err != nil {
			glog.Error(err)
			break
		}
		glog.Infof("accept from %s", c.RemoteAddr())
		cli := &authcli{con: c}
		go cli.serve()
	}
}
