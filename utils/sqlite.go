package utils

import (
	"os"
)

var (
	CurrentDirectory, _        = os.Getwd()
	DatabaseFilepath    string = CurrentDirectory + "/server/" + DatabaseFilename
)

const (
	DatabaseFilename string = "pwnts.db"
)
