package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"os"

	"github.com/s-christian/pwnts/utils"

	_ "github.com/mattn/go-sqlite3"
)

var (
	listenPort string = ":443"
)

func createCert() {
	config := tls.Config{}
	fmt.Println(config)
}

func main() {
	// Open database
	db, err := sql.Open("sqlite3", utils.DatabaseFilepath)
	if err != nil {
		utils.LogError(utils.Error, err, "Could not open sqlite3 database file \""+utils.DatabaseFilename+"\"")
		os.Exit(utils.ERR_GENERIC)
	}
	if db == nil {
		utils.Log(utils.Error, "db == nil, this should never happen")
		os.Exit(utils.ERR_DATABASE_INVALID)
	} else {
		utils.Log(utils.Info, "Opened database file")
	}
	defer db.Close()

	cert, err := tls.LoadX509KeyPair(utils.CurrentDirectory+"/pwnts.red.pem", utils.CurrentDirectory+"/pwnts_server_key.pem")
	if err != nil {
		utils.Log(utils.Error, "Couldn't load X509 keypair")
		os.Exit(1)
	}

	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := tls.Listen("tcp", listenPort, &tlsConfig)
	if err != nil {
		utils.Log(utils.Error, "Couldn't set up listener")
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Println("Listening...")

	// Main
	fmt.Println("Hello, world!")
}
