package main

/*
	Add flag for port number
*/

/*
	Flags:
		--test:				Sets the server's listener to listen on localhost instead of the proper
							network interface IP address.
		--port:				Port to listen on.
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
	"github.com/google/uuid"

	"github.com/s-christian/pwnts/utils"

	_ "github.com/mattn/go-sqlite3"
)

const (
	minCallbackTime time.Duration = 59 * time.Second
)

var (
	db *sql.DB
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
	remoteIP := remoteAddressSplit[0]
	var remotePort int
	fmt.Sscan(remoteAddressSplit[1], &remotePort)

	//rootAccess := remotePort < 1024 // TODO: I don't think Windows has privileged ports, what to do in this case?
	// if rootAccess {
	// 	fmt.Println("Double pwnts, yay!")
	// }

	logPrefix := "\t\t[" + conn.RemoteAddr().String() + "]"

	err := conn.SetReadDeadline(time.Now().Add(time.Second * 1))
	utils.CheckError(utils.Warning, err, logPrefix, "Setting read deadline failed, this is weird")

	readBuffer := make([]byte, 1024) // must be initialized for conn.Read, therefore we use make()
	numBytes, err := conn.Read(readBuffer)
	if err != nil {
		utils.LogError(utils.Warning, err, logPrefix, "Could not read bytes (took too long?)")
	} else if numBytes == 0 {
		utils.Log(utils.Warning, logPrefix, "No data received")
	} else {
		utils.Log(utils.Info, logPrefix, fmt.Sprint(numBytes), "bytes received")

		//readBuffer = readBuffer[:numBytes] // trim remaining empty bytes
		// Trim remaining empty bytes (bytes with a value of 0) from string,
		// without affecting readBuffer itself like the above line would do
		//readString := strings.TrimRight(string(readBuffer), string([]byte{0}))

		// TODO: Decryption of encrypted Agent message. Encryption on either side not yet implemented.

		/*
			--- Validate Agent callback format ---
		*/
		// The callback format assumes one piece of data, the Agent's UUID,
		// but allows for future flexibility with space-separated values.
		dataReceived := string(readBuffer[:numBytes])
		dataReceivedSplit := strings.Split(dataReceived, " ")

		agentUUID, err := uuid.Parse(dataReceivedSplit[0])

		// Invalid Agent callback
		if utils.CheckError(utils.Error, err, "Data received from non-Agent (Not a valid UUID)!") {
			return
		}

		// Valid Agent callback
		utils.Log(utils.List, "\t\t\tCallback from agent", agentUUID.String())

		// Agent is only testing connection, no additional processing needed
		// Response looks like "UUID TEST"
		if len(dataReceivedSplit) > 1 && dataReceivedSplit[1] == "TEST" {
			utils.Log(utils.Done, "\t\t\tAgent is testing connection, do nothing")
			return
		}

		/*
			--- Validate Agent registration ---
			: Check that Agent is known to us (registered in our db)
		*/
		checkAgentRegistrationSQL := `
			SELECT * FROM Agents
			WHERE agent_uuid = ?
		`
		checkAgentRegistrationStatement, err := db.Prepare(checkAgentRegistrationSQL)
		if utils.CheckError(utils.Error, err, "Could not create CheckAgentRegistration statement") {
			return
		}

		// TODO: change Query() to QueryRow()
		agentRegistrationRows, err := checkAgentRegistrationStatement.Query(agentUUID.String())
		if utils.CheckError(utils.Warning, err, "Could not execute CheckAgentRegistration statement") {
			return
		}

		knownAgent := agentRegistrationRows.Next()

		// Unknown (non-registered) Agent UUID
		if !knownAgent {
			utils.Log(utils.Error, "\t\t\tAgent", agentUUID.String(), "is unknown!")
			return
		}

		// Agent is known, continue
		// All timestamps are in seconds from the UNIX epoch
		var dbAgentUUID string
		var dbAgentTeam int
		var dbServerPrivateKey string
		var dbAgentPublicKey string
		var dbAgentDate int
		var dbAgentRootDate int
		agentRegistrationRows.Scan(&dbAgentUUID, &dbAgentTeam, &dbServerPrivateKey, &dbAgentPublicKey, &dbAgentDate, &dbAgentRootDate)
		utils.Log(utils.Done, "\t\t\tAgent (Team "+fmt.Sprint(dbAgentTeam)+") is known: created", time.Unix(int64(dbAgentDate), 0).String())

		// let go of db lock
		checkAgentRegistrationStatement.Close()
		agentRegistrationRows.Close()

		/*
			--- Check if callback source IP is in scope ---
		*/
		checkSourceIPInScopeSQL := `
			SELECT * FROM TargetsInScope
			WHERE target_ipv4_address = ?
		`
		checkSourceIPInScopeStatement, err := db.Prepare(checkSourceIPInScopeSQL)
		if utils.CheckError(utils.Error, err, "Could not create CheckSourceIPInScope statement") {
			return
		}

		var dbTargetIP string
		var dbTargetValue int
		err = checkSourceIPInScopeStatement.QueryRow(remoteIP).Scan(&dbTargetIP, &dbTargetValue)
		if err == sql.ErrNoRows {
			utils.Log(utils.Error, "\t\t\tSource IP '"+remoteIP+"' is not in scope!")
			return
		} else if utils.CheckError(utils.Error, err, "Could not execute CheckSourceIPInScope statement") {
			return
		}

		utils.Log(utils.Done, "\t\t\tTarget '"+dbTargetIP+"' is in scope and has a value of '"+fmt.Sprint(dbTargetValue)+"'")

		// Let go of db lock
		checkSourceIPInScopeStatement.Close()

		/*
			--- Check time difference between last callback ---
		*/
		checkCallbackTimeDifferenceSQL := `
			SELECT time_unix FROM AgentCheckins
			WHERE agent_uuid = ?
			ORDER BY time_unix DESC
			LIMIT 1
		` // get only the most recent callback
		checkCallbackTimeDifferenceStatement, err := db.Prepare(checkCallbackTimeDifferenceSQL)
		if utils.CheckError(utils.Error, err, "Could not create CheckCallbackTimeDifference statement") {
			return
		}

		var callbackPoints int

		// UNIX time, uses seconds
		var dbLastAgentCheckin int64
		err = checkCallbackTimeDifferenceStatement.QueryRow(agentUUID.String()).Scan(&dbLastAgentCheckin)
		if err == sql.ErrNoRows { // first callback
			utils.Log(utils.List, "\t\t\tThis is this Agent's first callback")
			callbackPoints = 100 // pwn = 100 points at first, no matter what
		} else if utils.CheckError(utils.Warning, err, "Could not execute CheckCallbackTimeDifference statement") { // genuine error
			return
		} else { // not first callback
			// convert UNIX seconds to a time.Duration by multiplying by time.Second
			var checkinTimeDifference time.Duration = time.Duration(time.Now().Unix()-dbLastAgentCheckin) * time.Second
			utils.Log(utils.List, "\t\t\tLast callback was", checkinTimeDifference.String(), "ago")

			// Agent called back too soon, must be greater than minTime, skip this callback
			// In testing, callbacks have rarely came back 59 seconds apart instead of 60
			if checkinTimeDifference < minCallbackTime {
				utils.Log(utils.Warning, "\t\t\tAgent called back too soon, ignoring ("+checkinTimeDifference.String()+" < "+minCallbackTime.String()+")")
				return
			}

			callbackPoints = utils.CalculateCallbackPoints(checkinTimeDifference, dbTargetValue)

			utils.Log(utils.Done, "\t\t\tTime between callbacks = "+checkinTimeDifference.String()+", worth", fmt.Sprint(callbackPoints), "points")
		}

		// Let go of db lock
		checkCallbackTimeDifferenceStatement.Close()

		/*
			--- Add points for callback ---
		*/

		// actually we're using the current score in the moment, not a cumulative total,
		// so no need to do anything here for now.
		//println("hi")

		/*
			--- Register Agent checkin ---
		*/
		utils.Log(utils.Info, "\t\t\tRegistering new checkin")

		addCheckinSQL := `
			INSERT INTO AgentCheckins(agent_uuid, target_ipv4_address, time_unix)
			VALUES (?, ?, ?)
		`
		addCheckinStatement, err := db.Prepare(addCheckinSQL)
		if utils.CheckError(utils.Error, err, "Could not create AddCheckin statement") {
			return
		}

		_, err = addCheckinStatement.Exec(agentUUID.String(), remoteIP, time.Now().Unix())
		if utils.CheckError(utils.Error, err, "Could not execute AddCheckin statement") {
			return
		}

		utils.Log(utils.Done, "\t\t\tAgent checkin registered")

		// Let go of db lock
		addCheckinStatement.Close()
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

	cert, err := tls.LoadX509KeyPair(utils.CurrentDirectory+"/pwnts_cert.pem", utils.CurrentDirectory+"/pwnts_key.pem")
	if err != nil {
		utils.LogError(utils.Error, err, "Couldn't load X509 keypair")
		os.Exit(1)
	}

	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}

	return tls.Listen("tcp", localAddress, &tlsConfig)
}

func printBanner() {
	pwntsBannerDivider := "============================================="
	pwntsBanner :=
		` _______           _       _________ _______ 
(  ____ )|\     /|( (    /|\__   __/(  ____ \
| (    )|| )   ( ||  \  ( |   ) (   | (    \/
| (____)|| | _ | ||   \ | |   | |   | (_____ 
|  _____)| |( )| || (\ \) |   | |   (_____  )
| (      | || || || | \   |   | |         ) |
| )      | () () || )  \  |   | |   /\____) |
|/       (_______)|/    )_)   )_(   \_______)
`

	color.Magenta(pwntsBannerDivider)
	color.Red(pwntsBanner)
	color.Magenta(pwntsBannerDivider)

	fmt.Println()
}

func main() {
	// Flags, usage visible with `go run server.go --help`.
	//	 - Actually, I think attempting to use any flag that doesn't exist brings up the usage.
	// Flags can be used with '--name' or '-name', doesn't matter.

	// Optionally initialize database by creating tables with the "--init-db" flag
	var argQuiet bool
	var argTest bool
	var argPort int
	flag.BoolVar(&argQuiet, "quiet", false, "Don't print the banner")
	flag.BoolVar(&argTest, "test", false, "Listen on localhost instead of the default interface's IP address")
	flag.IntVar(&argPort, "port", 444, "Port to listen on")
	flag.Parse()

	if !argQuiet {
		printBanner()
	}

	// Open the Sqlite3 database
	utils.Log(utils.Info, "Opening database file")

	// Open database
	// make sure you don't use `:=` here as it would define its own locally-scoped variable
	db = utils.GetDatabaseHandle()

	defer utils.Close(db)

	// Validate the database connection and structure
	utils.ValidateDatabaseExit(db)

	var listenIP net.IP
	if argTest {
		listenIP = net.ParseIP("127.0.0.1")
	} else {
		listenIP = utils.GetHostIP()
	}

	listenAddress := fmt.Sprintf("%s:%d", listenIP.String(), argPort)

	// Set up TLS (encrypted) listener to listen for agent callbacks
	listener, err := setupListener(listenAddress)
	if err != nil {
		utils.LogError(utils.Error, err, "Couldn't set up listener on", listenAddress)
		os.Exit(1)
	}
	defer listener.Close()

	utils.Log(utils.Done, "Listening on", listenAddress)
	color.New(color.Bold, color.FgBlue).Printf("\n--------------- Listening for Callbacks ---------------\n")

	// Process callbacks
	listenForCallbacks(listener)
}
