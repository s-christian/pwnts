package main

/*
	Flags:
		--test:				Sets the server's listener to listen on localhost instead of the proper
							network interface IP address.
		--init-db:			Initialize the database by creating the Teams and Agents Sqlite3 tables.
		--register-targets:	Add targets by their IP address and point value. Targets are defined
							in the file "targets.txt" in the CSV format "ip,point_value".
*/

import (
	"bufio"
	"crypto/tls"
	"database/sql"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"

	"github.com/s-christian/pwnts/utils"

	_ "github.com/mattn/go-sqlite3"
)

const (
	localPort string = "444"
)

var (
	localIP string
	db      *sql.DB
)

func handleConnection(conn net.Conn) {
	// At the end, close the connection with error checking using the anonymous function
	defer func() {
		if err := conn.Close(); err != nil {
			utils.LogError(utils.Warning, err, "Failed to close connection")
		}
	}()

	remoteAddress := conn.RemoteAddr().String()
	remoteAddressSplit := strings.Split(remoteAddress, ":")
	remoteIP := remoteAddress[0]
	var remotePort int
	fmt.Sscan(remoteAddressSplit[1], &remotePort)

	//rootAccess := remotePort < 1024 // TODO: I don't think Windows has privileged ports, what to do in this case?
	// if rootAccess {
	// 	fmt.Println("Double pwnts, yay!")
	// }

	logPrefix := "\t\t[" + conn.RemoteAddr().String() + "]"

	err := conn.SetReadDeadline(time.Now().Add(time.Second * 1))
	if err != nil {
		utils.LogError(utils.Warning, err, logPrefix, "Setting read deadline failed, this is weird")
	}

	readBuffer := make([]byte, 1024) // must be initialized for conn.Read, therefore we use make()
	numBytes, err := conn.Read(readBuffer)
	if err != nil {
		utils.Log(utils.Warning, logPrefix, "Could not read bytes (took too long?)")
	} else if numBytes == 0 {
		utils.Log(utils.Warning, logPrefix, "No data received")
	} else {
		utils.Log(utils.Info, logPrefix, fmt.Sprint(numBytes), "bytes received")

		//readBuffer = readBuffer[:numBytes] // trim remaining empty bytes
		// Trim remaining empty bytes (bytes with a value of 0) from string,
		// without affecting readBuffer itself like the above line would do
		//readString := strings.TrimRight(string(readBuffer), string([]byte{0}))

		// TODO: Decryption of encrypted Agent message. Encryption on either side not yet implemented.

		// The callback format assumes one piece of data, the Agent's UUID,
		// but allows for future flexibility with space-separated values.
		dataReceived := string(readBuffer[:numBytes])
		dataReceivedSplit := strings.Split(dataReceived, " ")

		agentUUID, err := uuid.Parse(dataReceivedSplit[0])

		// Invalid Agent callback
		if err != nil {
			utils.LogError(utils.Warning, err, "Data received from non-Agent (not a valid UUID)!")
			return
		}

		// Valid Agent callback
		utils.Log(utils.List, "\t\t\tCallback from agent", agentUUID.String())

		// Agent is only testing connection, no entry needed
		if len(dataReceivedSplit) > 1 && dataReceivedSplit[1] == "TEST" {
			utils.Log(utils.Info, "\t\t\tAgent is testing connection")
			return
		}

		// Register Agent checkin
		utils.Log(utils.Info, "\t\t\tRegistering checkin")

		// Add AgentCheckins entry
		addCheckinSQL := `
			INSERT INTO AgentCheckins(agent_uuid, target_ipv4_address, time_unix)
			VALUES (?, ?, ?)
		`
		addCheckinStatement, err := db.Prepare(addCheckinSQL)
		if err != nil {
			utils.LogError(utils.Error, err, "Could not create AddCheckin statement")
			os.Exit(utils.ERR_GENERIC)
		}
		defer addCheckinStatement.Close()

		_, err = addCheckinStatement.Exec(agentUUID.String(), remoteIP, time.Now().Unix())
		if err != nil {
			utils.LogError(utils.Error, err, "Could not execute AddCheckin statement")
			return
		}

		utils.Log(utils.Done, "\t\t\tAgent checkin registered")
	}
}

// Handle the agent callback
func listenForCallbacks(listener net.Listener) {
	for { // infinite listening loop
		conn, err := listener.Accept()
		if err != nil {
			utils.Log(utils.Warning, "Error accepting connection from", conn.RemoteAddr().String())
			if err := conn.Close(); err != nil {
				utils.Log(utils.Warning, "Failed to close listener:", err.Error())
			}
			continue // skip the bad connection
		}
		utils.Log(utils.List, "Received connection from", conn.RemoteAddr().String())

		// Start a new GoRoutine to handle the connection
		go handleConnection(conn)
	}
}

// Configures and returns the TLS Listener
func setupListener(localAddress string) (net.Listener, error) {
	utils.Log(utils.Info, "Setting up listener on", localAddress)

	cwd, _ := os.Getwd()
	cert, err := tls.LoadX509KeyPair(cwd+"/pwnts.red.pem", cwd+"/pwnts_server_key.pem")
	if err != nil {
		utils.LogError(utils.Error, err, "Couldn't load X509 keypair")
		os.Exit(1)
	}

	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}

	return tls.Listen("tcp", localAddress, &tlsConfig)
}

// Get preferred outbound IP address of this machine
func getOutboundIP() net.IP {
	// Because it uses UDP, the destination doesn't actually have to exist.
	// This will give us the IP address we would normally use to connect out.
	garbageIP := "192.0.2.100"

	conn, err := net.Dial("udp", garbageIP+":80")
	if err != nil {
		utils.LogError(utils.Error, err, "Couldn't obtain outbound IP address")
		os.Exit(utils.ERR_GENERIC)
	}
	defer conn.Close()

	// We only want to IP, not "IP:port"
	localIP := conn.LocalAddr().(*net.UDPAddr)

	return localIP.IP
}

func validateDatabase() {
	utils.Log(utils.Info, "Validating database")

	// sanity check
	if db == nil {
		utils.Log(utils.Error, "db is nil for some reason")
		os.Exit(utils.ERR_DATABASE_INVALID)
	}

	if err := db.Ping(); err != nil {
		utils.Log(utils.Error, "Cannot connect to the database. Have you intialized the database with `go run site.go --init-db` yet?")
		panic(err)
	}

	// This query is equivalent to `.tables` within the sqlite CLI, according to
	// [this](https://sqlite.org/cli.html#querying_the_database_schema) documentation.
	// showTablesStatement, err := db.Prepare(`
	// 	SELECT name FROM sqlite_master
	// 		WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'
	// 	UNION ALL
	// 	SELECT name FROM sqlite_temp_master
	// 		WHERE type IN ('table','view')
	// 	ORDER BY 1;
	// `)
	// tableNames, err := db.Query(`
	// 	SELECT name FROM sqlite_master
	// 		WHERE type IN ('table') AND name NOT LIKE 'sqlite_%'
	// 	ORDER BY 1;
	// `)
	tableNames, err := db.Query(`
		SELECT name FROM sqlite_master
		WHERE type IN ('table') AND name NOT LIKE 'sqlite_%'
		ORDER BY 1
	`)
	if err != nil {
		utils.Log(utils.Error, "Unable to query for table names")
		os.Exit(utils.ERR_GENERIC)
	}
	defer tableNames.Close()

	// Iterate over returned rows to count and print all table names
	var tableName string
	tableCounter := 0
	utils.Log(utils.Info, "Printing tables:")
	for tableNames.Next() {
		err = tableNames.Scan(&tableName)
		if err != nil {
			utils.LogError(utils.Error, err, "Could not scan row for table name")
			os.Exit(utils.ERR_GENERIC)
		} else if tableName == "" {
			utils.Log(utils.Error, "Database appears to be empty (no tables!), please run `go run server.go --init-db` first")
			fmt.Println("Table = '" + tableName + "'")
			utils.Log(utils.Debug, "Error temporarily ignored for testing purposes")
			//os.Exit(ERR_DATABASE_INVALID)
		} else {
			tableCounter++
			color.Yellow("\t\t\t\t\t\t" + tableName)
		}
	}

	// Ensure we have the correct number of tables
	numExpectedTables := 4
	if tableCounter == numExpectedTables {
		utils.Log(utils.Done, "Database validated")
	} else {
		utils.Log(utils.Error, "Database is missing", fmt.Sprint(numExpectedTables-tableCounter), "tables, please run `go run server.go --init-db`")
		os.Exit(utils.ERR_DATABASE_INVALID)
	}
}

func registerTargets() {
	utils.Log(utils.Info, "Registering targets:")

	currentDirectory, _ := os.Getwd()
	targetsFile, err := os.Open(currentDirectory + "/server/targets.txt")
	if err != nil {
		utils.LogError(utils.Error, err, "Cannot open targets file")
		os.Exit(utils.ERR_GENERIC)
	}
	defer targetsFile.Close()

	addTargetSQL := `
		INSERT INTO TargetsInScope(target_ipv4_address, value)
		VALUES (?, ?)
	`
	addTargetStatement, err := db.Prepare(addTargetSQL)
	if err != nil {
		utils.LogError(utils.Error, err, "Could not create AddTarget statement")
		os.Exit(utils.ERR_GENERIC)
	}
	defer addTargetStatement.Close()

	scanner := bufio.NewScanner(targetsFile)
	addedCounter, lineCounter := 0, 0
	for scanner.Scan() {
		lineCounter++
		lineCSV := strings.Split(scanner.Text(), ",")

		var targetIP string = lineCSV[0]
		var targetValue int
		fmt.Sscan(lineCSV[1], &targetValue)

		_, err := addTargetStatement.Exec(targetIP, targetValue)
		if err != nil {
			utils.LogError(utils.Warning, err, "Could not add the following target:", scanner.Text())
			continue
		}

		addedCounter++
		color.Yellow("\t\t\t\t\t\tTarget IP: " + targetIP + ",\tValue: " + fmt.Sprint(targetValue))
	}

	targetsCount := db.QueryRow("SELECT COUNT(*) FROM TargetsInScope")
	var numTargets int
	targetsCount.Scan(&numTargets)

	utils.Log(utils.Done, "Registered", fmt.Sprintf("%d/%d", addedCounter, lineCounter), "targets")
	utils.Log(utils.Done, "There are now a total of", fmt.Sprint(numTargets), "targets in scope")
}

// Flag: --init-db
func initializeDatabase() {
	utils.Log(utils.Info, "Initializing database")
	utils.Log(utils.Debug, "If recreating the entire database, please manually remove the database file")

	// Create database file if it doesn't exist
	if _, err := os.Stat(utils.DatabaseFilepath); os.IsNotExist(err) {
		dbFile, err := os.Create(utils.DatabaseFilepath)
		if err != nil {
			utils.LogError(utils.Error, err, "Could not create database file")
			os.Exit(utils.ERR_GENERIC)
		}
		utils.Log(utils.Done, "Created database file \""+utils.DatabaseFilename+"\"")
		dbFile.Close()
	}

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

	createTablesCommands, err := os.ReadFile(utils.CurrentDirectory + "/server/create_tables.txt")
	if err != nil {
		utils.LogError(utils.Error, err, "Could not read \"create_tables.txt\"")
		os.Exit(utils.ERR_GENERIC)
	}

	statement, err := db.Prepare(string(createTablesCommands))
	if err != nil {
		utils.LogError(utils.Error, err, "Could not create statement for creation of tables")
		os.Exit(utils.ERR_GENERIC)
	}
	defer statement.Close()

	// statement, err := db.Prepare(`
	// 	CREATE TABLE IF NOT EXISTS "Teams" (
	// 		"id"	INTEGER NOT NULL UNIQUE,
	// 		"name"	TEXT NOT NULL UNIQUE,
	// 		"score"	INTEGER NOT NULL DEFAULT 0,
	// 		"created_date"	TEXT NOT NULL,
	// 		PRIMARY KEY("id" AUTOINCREMENT)
	// 	);
	// `)
	// if err != nil {
	// 	utils.Log(utils.Error, "Could not create statement for table Teams")
	// 	panic(err)
	// }
	// defer statement.Close()

	_, err = statement.Exec()
	if err != nil {
		utils.LogError(utils.Error, err, "Could not create tables")
		os.Exit(utils.ERR_GENERIC)
	}

	// if err != nil {
	// 	utils.Log(utils.Error, "Could not create table Teams")
	// 	panic(err)
	// }

	// statement, err = db.Prepare(`
	// 	CREATE TABLE IF NOT EXISTS "Agents" (
	// 		"uuid"	TEXT NOT NULL UNIQUE,
	// 		"team_id"	INTEGER NOT NULL,
	// 		"server_private_key"	TEXT NOT NULL UNIQUE,
	// 		"agent_public_key"	TEXT NOT NULL UNIQUE,
	// 		"source_ip"	TEXT NOT NULL,
	// 		"last_source_port"	INTEGER,
	// 		"first_checkin"	TEXT,
	// 		"last_checkin"	TEXT,
	// 		"total_score"	INTEGER NOT NULL DEFAULT 0,
	// 		"last_score"	INTEGER,
	// 		"created_date"	TEXT NOT NULL,
	// 		"root_date"	TEXT,
	// 		FOREIGN KEY("team_id") REFERENCES "Teams"("id"),
	// 		PRIMARY KEY("uuid")
	// 	);
	// `)
	// if err != nil {
	// 	utils.Log(utils.Error, "Could not create statement for table Agents")
	// 	panic(err)
	// }
	// defer statement.Close()

	// _, err = statement.Exec()
	// if err != nil {
	// 	utils.Log(utils.Error, "Could not create table Agents")
	// 	panic(err)
	// }

	utils.Log(utils.Done, "Database initialized")
}

func printBanner() {
	color.Magenta("=============================================")
	color.Red(" _______           _       _________ _______ ")
	color.Red("(  ____ )|\\     /|( (    /|\\__   __/(  ____ \\")
	color.Red("| (    )|| )   ( ||  \\  ( |   ) (   | (    \\/")
	color.Red("| (____)|| | _ | ||   \\ | |   | |   | (_____ ")
	color.Red("|  _____)| |( )| || (\\ \\) |   | |   (_____  )")
	color.Red("| (      | || || || | \\   |   | |         ) |")
	color.Red("| )      | () () || )  \\  |   | |   /\\____) |")
	color.Red("|/       (_______)|/    )_)   )_(   \\_______)")
	color.Magenta("=============================================")
	fmt.Println()
}

func main() {
	// Flags, usage visible with `go run server.go --help`.
	//	 - Actually, I think attempting to use any flag that doesn't exist brings up the usage.
	// Flags can be used with one or two '-', doesn't matter.

	// Optionally initialize database by creating tables with the "--init-db" flag
	var argInitDB bool
	var argRegisterTargets bool
	var argQuiet bool
	var argTest bool

	flag.BoolVar(&argInitDB, "init-db", false, "Initialize the database by creating the Teams and Agents Sqlite3 tables")
	flag.BoolVar(&argRegisterTargets, "register-targets", false, "Add targets by their IP address and point value. Targets are defined in the file \"targets.txt\" in the CSV format \"ip,point_value\".")
	flag.BoolVar(&argQuiet, "quiet", false, "Don't print the banner")
	flag.BoolVar(&argTest, "test", false, "Listen on localhost instead of the default interface's IP address")
	flag.Parse()

	if !argQuiet {
		printBanner()
	}

	if argInitDB {
		initializeDatabase()
		os.Exit(0)
	}

	// Open the Sqlite3 database
	utils.Log(utils.Info, "Opening database file")

	// Open database
	var err error
	db, err = sql.Open("sqlite3", utils.DatabaseFilepath)
	if err != nil {
		utils.LogError(utils.Error, err, "Could not open sqlite3 database file \""+utils.DatabaseFilename+"\"")
		os.Exit(utils.ERR_GENERIC)
	}
	if db == nil {
		utils.Log(utils.Error, "db == nil, this should never happen")
		os.Exit(utils.ERR_DATABASE_INVALID)
	}

	utils.Log(utils.Info, "Opened database file")

	defer db.Close()

	// Validate the database connection and structure
	validateDatabase()

	// Optionally register targets from the file "server/targets.txt"
	// Flag: --register-targets
	if argRegisterTargets {
		registerTargets()
		os.Exit(0)
	}

	if argTest {
		localIP = "127.0.0.1"
	} else {
		localIP = getOutboundIP().String()
	}

	// Set up TLS (encrypted) listener to listen for agent callbacks
	localAddress := localIP + ":" + localPort
	listener, err := setupListener(localAddress)
	if err != nil {
		utils.LogError(utils.Error, err, "Couldn't set up listener on", localAddress)
		os.Exit(1)
	}
	defer listener.Close()

	utils.Log(utils.Done, "Listening on", localAddress)
	color.New(color.Bold, color.FgBlue).Printf("\n--------------- Listening for Callbacks ---------------\n")

	// Process callbacks
	listenForCallbacks(listener)
}
