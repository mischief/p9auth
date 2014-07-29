// +build !plan9

package main

import (
	"upper.io/db/postgresql"
	"upper.io/db/sqlite"
)

var (
	sqladapters = []string{
		sqlite.Adapter,
		postgresql.Adapter,
	}
)
