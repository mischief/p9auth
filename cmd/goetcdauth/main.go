package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/mischief/p9auth"

	"github.com/coreos/go-etcd/etcd"
)

var (
	machine = ""
	listen  = ""
)

func env(key, def string) string {
	if x := os.Getenv(key); x != "" {
		return x
	}
	return def
}

func init() {
	flag.StringVar(&listen, "l", env("AUTHSRV_ADDR", ":567"), "auth server address")
	flag.StringVar(&machine, "machines", env("ETCD_MACHINES", "http://127.0.0.1:4001"), "machine address(es) running etcd")
}

type keyfsdb struct {
}

func (*keyfsdb) Key(user string) (key [p9auth.DESKEYLEN]byte, err error) {

	machines := strings.Split(machine, ",")
	cl := etcd.NewClient(machines)

	r, err := cl.Get(fmt.Sprintf("/authsrv/%s/key", user), false, false)
	if err != nil {
		return key, err
	}

	if r.Node.Dir == true {
		return key, fmt.Errorf("etcd key is a directory")
	}

	data, err := base64.StdEncoding.DecodeString(r.Node.Value)
	if err != nil {
		return key, err
	}

	copy(key[:], data)

	return key, nil
}

func main() {
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile)
	listener, err := net.Listen("tcp", listen)
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
