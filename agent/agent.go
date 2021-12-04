package main

/*
	Flags:
		--info:		Print's the Agent's configuration info.
		--test:		Tests the Agent's connection to the callback server.
		--single:	Only send a single callback, don't wait in a loop
					(i.e. routine callbacks are handled by something else,
					such as a cron job).
*/

// Fun thought: can you change the Agent process name to whatever you want?
// https://github.com/erikdubbelboer/gspt
// For scoring: Regex if it has "malware" in the title, double points for style?

import (
	"fmt"
	"os"
	"time"

	"crypto/tls"
	"net"

	"github.com/olekukonko/tablewriter"
	"github.com/s-christian/pwnts/utils"

	"github.com/fatih/color"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type agentInfoStruct struct {
	ServerPublicKey string
	AgentUUID       uuid.UUID
}

var (
	serverPublicKey string          = "555"
	agentUUID       uuid.UUID       = uuid.New()
	agentInfo       agentInfoStruct = agentInfoStruct{ServerPublicKey: serverPublicKey, AgentUUID: agentUUID}
	// testing: agentUUID, _                 = uuid.Parse("ef1a6a78-0d95-490a-a07f-9607e00b96ce")

	localPort    int         = 1337
	localAddress net.TCPAddr = net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort}
	//localAddress      net.TCPAddr   = net.TCPAddr{Port: localPort}

	serverIP      string      = "127.0.0.1"
	serverPort    int         = 444
	serverAddress net.TCPAddr = net.TCPAddr{IP: net.ParseIP(serverIP), Port: serverPort}

	tlsConfig                tls.Config    = tls.Config{InsecureSkipVerify: true}
	callbackFrequencyMinutes time.Duration = 1 * time.Minute
)

func callback() {
	// All errors are ignored since we want to keep trying, infinitely

	// TODO: Allow for custom local port to be specified, currently unsure how to do this.
	// Can do it with net.Dial(), but there's no option in tls.Dial()
	conn, err := tls.Dial("tcp", serverIP+":"+fmt.Sprint(serverPort), &tlsConfig)
	//conn, err := net.DialTCP("tcp", &localAddress, &serverAddress)
	if err != nil {
		return
	}

	err = conn.SetWriteDeadline(time.Now().Add(time.Second * 1))
	if err != nil {
		return
	}

	callbackMessage := agentUUID.String()
	numBytes, err := conn.Write([]byte(callbackMessage))
	if err != nil { // couldn't establish connection?
		return
	} else if numBytes == 0 { // somehow wasn't able to send any data
		return
	}
}

// Test Agent's connection to the server. Only used if the `--test` flag is passed.
func testServer() {
	utils.Log(utils.Info, "Testing connection to server...")
	utils.Log(utils.Info, "Local Address: ", localAddress.IP.String()+":"+fmt.Sprint(localAddress.Port))
	utils.Log(utils.Info, "Server Address:", serverAddress.IP.String()+":"+fmt.Sprint(serverAddress.Port))

	// TODO: Allow for custom local port to be specified, currently unsure how to do this.
	// Can do it with net.Dial(), but there's no option in tls.Dial()
	conn, err := tls.Dial("tcp", serverIP+":"+fmt.Sprint(serverPort), &tlsConfig)
	if err != nil {
		utils.LogError(utils.Error, err, "Could not connect to server")
		os.Exit(utils.ERR_CONNECTION)
	}

	err = conn.SetWriteDeadline(time.Now().Add(time.Second * 1))
	if err != nil {
		utils.LogError(utils.Warning, err, "Setting write deadline failed, this is weird")
	}

	testMessage := fmt.Sprintf("%s %s", agentUUID.String(), "TEST")
	numBytes, err := conn.Write([]byte(testMessage))
	if err != nil {
		utils.LogError(utils.Error, err, "Could not send data to server (write timeout)")
		os.Exit(utils.ERR_WRITE)
	} else if numBytes == 0 {
		utils.LogError(utils.Error, err, "Could not send data to server (sent 0 bytes)")
		os.Exit(utils.ERR_BYTES)
	}

	utils.Log(utils.Done, "Wrote", fmt.Sprint(numBytes), "bytes to server")
	utils.Log(utils.Done, "Works!")

	/* Note:
	We don't want to close the connection ourselves, because then
	that would put our local port into TIME_WAIT mode, meaning we
	won't be able to re-use it for a minute or two. Instead, we
	want the server to close it for us, so we can re-use the socket
	immediately.
	*/
}

func (info agentInfoStruct) printAgentInfo() {
	data := []string{info.ServerPublicKey, info.AgentUUID.String()}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Server Public Key", "Agent UUID"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor},
	)
	table.SetColumnColor(
		tablewriter.Colors{tablewriter.FgRedColor},
		tablewriter.Colors{tablewriter.FgRedColor},
	)

	table.Append(data)

	color.HiRed("[^] AGENT INFO")
	table.Render()
}

func main() {
	// Intentionally not using the "flag" package because we never want to print usage information
	single := false
	if len(os.Args) > 1 { // contains a command-line flag
		switch os.Args[1] {
		case "--info":
			agentInfo.printAgentInfo()
			return

		case "--test":
			testServer()
			return

		case "--single":
			single = true
		}
	}

	// First callback
	callback()

	// Call back to server according to the callback frequency in minutes
	if !single {
		for range time.Tick(callbackFrequencyMinutes) {
			callback()
		}
	}
}
