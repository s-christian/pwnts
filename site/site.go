package main

/*
	Flags:
		--init-db:	Initialize the database by creating the Teams and Agents Sqlite3 tables.
*/

/*
CREATE TABLE IF NOT EXISTS "Teams" (
	"id"	INTEGER NOT NULL UNIQUE,
	"name"	TEXT NOT NULL UNIQUE,
	"score"	INTEGER NOT NULL DEFAULT 0,
	"created_date"	TEXT NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);

CREATE TABLE IF NOT EXISTS "Agents" (
	"uuid"	TEXT NOT NULL UNIQUE,
	"team_id"	INTEGER NOT NULL,
	"server_private_key"	TEXT NOT NULL UNIQUE,
	"agent_public_key"	TEXT NOT NULL UNIQUE,
	"source_ip"	TEXT NOT NULL,
	"last_source_port"	INTEGER,
	"first_checkin"	TEXT,
	"last_checkin"	TEXT,
	"total_score"	INTEGER NOT NULL DEFAULT 0,
	"last_score"	INTEGER,
	"created_date"	TEXT NOT NULL,
	"root_date"	TEXT,
	FOREIGN KEY("team_id") REFERENCES "Teams"("id"),
	PRIMARY KEY("uuid")
);
*/

import (
	"crypto/tls"
	"database/sql"
	"flag"
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

func initializeDatabase(db *sql.DB) {
	statement, err := db.Prepare(`
		CREATE TABLE IF NOT EXISTS "Teams" (
			"id"	INTEGER NOT NULL UNIQUE,
			"name"	TEXT NOT NULL UNIQUE,
			"score"	INTEGER NOT NULL DEFAULT 0,
			"created_date"	TEXT NOT NULL,
			PRIMARY KEY("id" AUTOINCREMENT)
		);
	`)
	if err != nil {
		utils.Log(utils.Error, "Could not create statement for table Teams")
		panic(err)
	}
	defer statement.Close()

	_, err = statement.Exec()
	if err != nil {
		utils.Log(utils.Error, "Could not create table Teams")
		panic(err)
	}

	statement, err = db.Prepare(`
		CREATE TABLE IF NOT EXISTS "Agents" (
			"uuid"	TEXT NOT NULL UNIQUE,
			"team_id"	INTEGER NOT NULL,
			"server_private_key"	TEXT NOT NULL UNIQUE,
			"agent_public_key"	TEXT NOT NULL UNIQUE,
			"source_ip"	TEXT NOT NULL,
			"last_source_port"	INTEGER,
			"first_checkin"	TEXT,
			"last_checkin"	TEXT,
			"total_score"	INTEGER NOT NULL DEFAULT 0,
			"last_score"	INTEGER,
			"created_date"	TEXT NOT NULL,
			"root_date"	TEXT,
			FOREIGN KEY("team_id") REFERENCES "Teams"("id"),
			PRIMARY KEY("uuid")
		);
	`)
	if err != nil {
		utils.Log(utils.Error, "Could not create statement for table Agents")
		panic(err)
	}
	defer statement.Close()

	_, err = statement.Exec()
	if err != nil {
		utils.Log(utils.Error, "Could not create table Agents")
		panic(err)
	}
}

func main() {
	// Open database
	db, err := sql.Open("sqlite3", "./pwnts.db")
	if err != nil {
		utils.Log(utils.Error, "Couldn't open sqlite3 database file")
		panic(err)
	}
	if db != nil {
		utils.Log(utils.Done, "Opened database file")
	} else {
		panic(utils.LogMessage(utils.Done, "db == nil, this should never happen"))
	}
	defer db.Close()

	// Optionally initialize database by creating tables with the "--init-db" flag
	var initDB bool
	flag.BoolVar(&initDB, "--init-db", false, "Initialize the database by creating the Teams and Agents Sqlite3 tables")
	flag.Parse()

	if initDB {
		initializeDatabase(db)
	}

	cert, err := tls.LoadX509KeyPair("../pwnts.red.pem", "../pwnts_server_key.pem")
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
