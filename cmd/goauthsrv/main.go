// Goauthsrv implements a Plan 9 authentication server that can speak a little
// bit of p9sk1. It requires that keyfs is accessible over tcp, but it should
// be able to open plain files (if keyfs is mounted) in the future.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/mischief/p9auth"

	"code.google.com/p/go9p/p"
	"code.google.com/p/go9p/p/clnt"
)

type FakeUser string

func (u *FakeUser) Name() string            { return string(*u) }
func (u *FakeUser) Id() int                 { return 61508 }
func (u *FakeUser) Groups() []p.Group       { return []p.Group{u} }
func (u *FakeUser) IsMember(g p.Group) bool { return true }
func (u *FakeUser) Members() []p.User       { return []p.User{u} }

var (
	myuser     = FakeUser("auth")
	keyaddr    = flag.String("k", "127.0.0.1:61509", "key server")
	listenaddr = flag.String("l", ":567", "auth server address")
)

type keyfsdb struct {
}

func (*keyfsdb) Key(user, dom string) (key [p9auth.DESKEYLEN]byte, err error) {
	p9, err := clnt.Mount("tcp", *keyaddr, "", &myuser)
	if err != nil {
		return
	}

	defer p9.Unmount()

	f, err := p9.FOpen(fmt.Sprintf("%s/key", user), p.OREAD)
	if err != nil {
		return key, fmt.Errorf("findkey: %s", err)
	}
	defer f.Close()

	if n, err := f.ReadAt(key[:], 0); n != p9auth.DESKEYLEN {
		return key, fmt.Errorf("findkey: short key: %d", n)
	} else if err != nil {
		return key, fmt.Errorf("findkey: %s", err)
	}

	return key, nil
}

func main() {
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile)
	listener, err := net.Listen("tcp", *listenaddr)
	if err != nil {
		logger.Fatal(err)
	}

	keydb := &keyfsdb{}
	authsrv := p9auth.NewAuthSrv(listener, keydb)

	authsrv.SetLogger(logger)

	if err := authsrv.Serve(); err != nil {
		logger.Fatal(err)
	}
}
