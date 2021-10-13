package main

/*
	Flags:
		--info:		Print's the Agent's configuration info.
		--test:		Tests the Agent's connection to the callback server.
*/

import (
	"fmt"
	"os"

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

const (
	ERR_GENERIC    int = 10
	ERR_CONNECTION int = 11
	ERR_WRITE      int = 12
	ERR_BYTES      int = 13
)

var (
	serverPublicKey string          = "555"
	agentUUID       uuid.UUID       = uuid.New()
	agentInfo       agentInfoStruct = agentInfoStruct{ServerPublicKey: serverPublicKey, AgentUUID: agentUUID}
	localPort       int             = 1337
	//localAddress    net.TCPAddr     = net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort}
	localAddress  net.TCPAddr = net.TCPAddr{Port: localPort}
	serverIP      string      = "127.0.0.1"
	serverPort    int         = 444
	serverAddress net.TCPAddr = net.TCPAddr{IP: net.ParseIP(serverIP), Port: serverPort}
	tlsConfig     tls.Config  = tls.Config{InsecureSkipVerify: true}
)

func callback() {
	// TODO: Allow for custom local port to be specified, currently unsure how to do this.
	//       Can do it with net.Dial(), but there's no option in tls.Dial()...
	conn, err := tls.Dial("tcp", serverIP+":"+fmt.Sprint(serverPort), &tlsConfig)
	//conn, err := net.DialTCP("tcp", &localAddress, &serverAddress)
	if err != nil {
		os.Exit(ERR_CONNECTION) // we don't want to output anything if we're trying to be sneaky
	}

	callbackMessage := agentUUID.String()
	numBytes, err := conn.Write([]byte(callbackMessage))
	if err != nil { // couldn't establish connection?
		os.Exit(ERR_WRITE)
	} else if numBytes == 0 { // somehow wasn't able to send any data
		os.Exit(ERR_BYTES)
	}
}

// Test Agent's connection to the server. Only used if the `--test` flag is passed.
func testServer() {
	serverIP = "127.0.0.1" // testing uses localhost

	utils.Log(utils.Info, "Testing connection to server...")
	utils.Log(utils.Info, "Local Address: ", localAddress.IP.String()+":"+fmt.Sprint(localAddress.Port))
	utils.Log(utils.Info, "Server Address:", serverAddress.IP.String()+":"+fmt.Sprint(serverAddress.Port))

	// TODO: Allow for custom local port to be specified, currently unsure how to do this.
	//       Can do it with net.Dial(), but there's no option in tls.Dial()...
	conn, err := tls.Dial("tcp", serverIP+":"+fmt.Sprint(serverPort), &tlsConfig)
	if err != nil {
		utils.LogError(utils.Error, err, "Could not connect to server")
		os.Exit(ERR_CONNECTION)
	}

	testMessage := "Agent " + agentUUID.String() + " testing connection"
	numBytes, err := conn.Write([]byte(testMessage))
	if err != nil {
		utils.LogError(utils.Error, err, "Could not send data to server")
		os.Exit(ERR_WRITE)
	} else if numBytes == 0 {
		utils.LogError(utils.Error, err, "Sent 0 bytes")
		os.Exit(ERR_BYTES)
	}

	utils.Log(utils.Done, "Wrote", fmt.Sprint(numBytes), "bytes to server")
	utils.Log(utils.Done, "Works!")

	/* Note:
	We don't want to close the connection ourselves, because then
	that would put our local port into TIME_WAIT mode, meaning we
	won't be able to re-use it for a minute or two. Instead, we
	want the server to close it for us, so we can re-use the socket
	immediately if we want to.
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
	// Optionally print this Agent's information
	// Intentionally not using the "flag" package because we never want to print usage information
	if len(os.Args) > 1 { // contains a command-line flag
		if os.Args[1] == "--info" {
			agentInfo.printAgentInfo()
			return
		} else if os.Args[1] == "--test" {
			testServer()
			return
		}
	}

	// Call back to server
	callback()
}
