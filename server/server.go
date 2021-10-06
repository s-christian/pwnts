package main

/*
	Flags:
		--test:		Sets the server's listener to listen on localhost
					instead of the proper network interface IP address.
*/

import (
	"crypto/tls"
	"database/sql"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/s-christian/pwnts/utils"

	_ "github.com/mattn/go-sqlite3"
)

const (
	ERR_GENERIC          int = 20
	ERR_DATABASE_INVALID int = 21
	localPort                = "444"
)

var (
	localIP string
)

func handleConnection(conn net.Conn) {
	// At the end, close the connection with error checking using the anonymous function
	defer func() {
		if err := conn.Close(); err != nil {
			utils.Log(utils.Warning, "Failed to close connection")
		}
	}()

	remoteAddress := conn.RemoteAddr().String()
	logPrefix := "\t\t[" + remoteAddress + "]"

	var remotePort int
	fmt.Sscan(strings.Split(remoteAddress, ":")[1], &remotePort)
	rootAccess := remotePort < 1024 // TODO: I don't think Windows has privileged ports, what to do in this case?
	if rootAccess {
		fmt.Println("Double pwnts, yay!")
	}

	err := conn.SetReadDeadline(time.Now().Add(time.Second * 1))
	if err != nil {
		utils.Log(utils.Warning, logPrefix, "Setting read deadline failed, this is weird")
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
		utils.Log(utils.Info, logPrefix, "String received:")
		utils.Log(utils.List, "\t\t\t\""+string(readBuffer[:numBytes])+"\"")
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
		utils.Log(utils.Error, "Couldn't obtain outbound IP address [failed at func getOutBoundIP()]")
		panic(err)
	}
	defer conn.Close()

	// We only want to IP, not "IP:port"
	localIP := conn.LocalAddr().(*net.UDPAddr)

	return localIP.IP
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
	var argQuiet bool
	var argTest bool

	flag.BoolVar(&argQuiet, "quiet", false, "Don't print the banner")
	flag.BoolVar(&argTest, "test", false, "Listen on localhost instead of the default interface's IP address")
	flag.Parse()

	if !argQuiet {
		printBanner()
	}
	if argTest {
		localIP = "127.0.0.1"
	} else {
		localIP = getOutboundIP().String()
	}

	// Open the Sqlite3 database
	utils.Log(utils.Info, "Opening database file")

	db, err := sql.Open("sqlite3", "./pwnts.db")
	if err != nil {
		utils.Log(utils.Error, "Couldn't open sqlite3 database file. Have you initialized the database with `go run site.go --init-db` yet?")
		panic(err)
	}
	if db != nil {
		utils.Log(utils.Done, "Opened database file")
	} else {
		panic(utils.LogMessage(utils.Done, "db == nil, this should never happen"))
	}
	defer db.Close()

	// Test the database connection
	utils.Log(utils.Info, "Validating database")

	if err = db.Ping(); err != nil {
		utils.Log(utils.Error, "Cannot connect to the database. Have you intialized the database with `go run site.go --init-db` yet?")
		panic(err)
	}

	// This query is equivalent to `.tables` within the sqlite CLI, according to
	// [this](https://sqlite.org/cli.html#querying_the_database_schema) documentation.
	showTablesStatement, err := db.Prepare(`
		SELECT name FROM sqlite_master
			WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'
		UNION ALL
		SELECT name FROM sqlite_temp_master
			WHERE type IN ('table','view')
		ORDER BY 1
	`)
	if err != nil {
		utils.Log(utils.Error, "Unable to construct statement for table names")
		os.Exit(ERR_GENERIC)
	}

	showTablesQuery, err := showTablesStatement.Query()
	if err != nil {
		utils.Log(utils.Error, "Unable to query for table names")
		os.Exit(ERR_GENERIC)
	}

	var table string
	showTablesQuery.Scan(&table)
	if table == "" {
		utils.Log(utils.Error, "Database appears to be empty (no tables!), please run `go run site.go --init-db` first")
		utils.Log(utils.Debug, "Error temporarily ignored for testing purposes")
		//os.Exit(ERR_DATABASE_INVALID)
	} else {
		utils.Log(utils.Done, "Database validated")
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
