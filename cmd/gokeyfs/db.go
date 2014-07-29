package main

import (
	"upper.io/db"
)

type User struct {
	Dbid     int    `db:"id"`
	Uid      int    `db:"uid"`
	Username string `db:"username"`
	//Deskey   string `db:"deskey"`
	Password string `db:"password"`
}

func keydbopen(dbtype string, dbsettings db.Settings) (*keydb, error) {
	db, err := db.Open(dbtype, dbsettings)
	if err != nil {
		return nil, err
	}

	return &keydb{db}, nil
}

type keydb struct {
	dbm db.Database
}

func (k *keydb) All() ([]User, error) {
	var u []User

	table, err := k.dbm.Collection("users")
	if err != nil {
		return nil, err
	}

	res := table.Find()
	defer res.Close()

	if err = res.All(&u); err != nil {
		return nil, err
	}

	return u, nil
}

func (k *keydb) ByUsername(name string) (*User, error) {
	var u User

	table, err := k.dbm.Collection("users")
	if err != nil {
		return nil, err
	}

	res := table.Find(db.Cond{"username": name})
	defer res.Close()

	if err = res.One(&u); err != nil {
		return nil, err
	}

	return &u, nil
}

func (k *keydb) ByUid(id int) (*User, error) {
	var u User

	table, err := k.dbm.Collection("users")
	if err != nil {
		return nil, err
	}

	res := table.Find(db.Cond{"uid": id})
	defer res.Close()

	if err = res.One(&u); err != nil {
		return nil, err
	}

	return &u, nil
}
