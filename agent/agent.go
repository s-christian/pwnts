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

type AgentInfoStruct struct {
	AgentUUID         string
	LocalAddress      net.TCPAddr
	ServerAddress     net.TCPAddr
	CallbackFrequency time.Duration
	ServerPublicKey   string
}

var (
	AgentUUID string // set during compilation

	LocalPortString string // set during compilation
	localPort       int
	localAddress    net.TCPAddr
	// testing: localAddress      net.TCPAddr   = net.TCPAddr{Port: LocalPort}

	ServerIP         string // set during compilation
	ServerPortString string // set during compilation
	serverPort       int
	serverAddress    net.TCPAddr
	serverPublicKey  string = "555"

	CallbackFrequencyMinutesString string // set during compilation
	callbackFrequencyMinutes       time.Duration

	agentInfo AgentInfoStruct
	// testing: AgentUUID, _                 = uuid.Parse("ef1a6a78-0d95-490a-a07f-9607e00b96ce")

	tlsConfig tls.Config = tls.Config{InsecureSkipVerify: true}
)

func callback() {
	// All errors are ignored since we want to keep trying, infinitely

	// TODO: Allow for custom local port to be specified, currently unsure how to do this.
	// Can do it with net.Dial(), but there's no option in tls.Dial()
	conn, err := tls.Dial("tcp", ServerIP+":"+ServerPortString, &tlsConfig)
	//conn, err := net.DialTCP("tcp", &localAddress, &serverAddress)
	if err != nil {
		return
	}

	err = conn.SetWriteDeadline(time.Now().Add(time.Second * 1))
	if err != nil {
		return
	}

	callbackMessage := AgentUUID
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
	conn, err := tls.Dial("tcp", ServerIP+":"+ServerPortString, &tlsConfig)
	if err != nil {
		utils.LogError(utils.Error, err, "Could not connect to server")
		os.Exit(utils.ERR_CONNECTION)
	}

	err = conn.SetWriteDeadline(time.Now().Add(time.Second * 1))
	if err != nil {
		utils.LogError(utils.Warning, err, "Setting write deadline failed, this is weird")
	}

	testMessage := fmt.Sprintf("%s %s", AgentUUID, "TEST")
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

func (info AgentInfoStruct) printAgentInfo() {
	data := []string{info.AgentUUID, info.LocalAddress.String(), info.ServerAddress.String(), info.CallbackFrequency.String(), info.ServerPublicKey}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Agent UUID", "Local Address", "ServerAddress", "Callback Frequency", "Server Public Key"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor},
	)
	table.SetColumnColor(
		tablewriter.Colors{tablewriter.FgRedColor},
		tablewriter.Colors{tablewriter.FgRedColor},
		tablewriter.Colors{tablewriter.FgRedColor},
		tablewriter.Colors{tablewriter.FgRedColor},
		tablewriter.Colors{tablewriter.FgRedColor},
	)

	table.Append(data)

	color.HiRed("[^] AGENT INFO")
	table.Render()
}

func main() {
	// Initialize variables if they weren't provide during the build
	if LocalPortString == "" {
		LocalPortString = "1337"
	}
	if AgentUUID == "" {
		AgentUUID = uuid.New().String()
	}
	if ServerPortString == "" {
		ServerPortString = "444"
	}
	if CallbackFrequencyMinutesString == "" {
		CallbackFrequencyMinutesString = "1"
	}
	if ServerIP == "" {
		ServerIP = "127.0.0.1"
	}

	// Set up variables
	_, err := fmt.Sscan(LocalPortString, &localPort)
	utils.CheckErrorExit(utils.Error, err, utils.ERR_SCAN, "Could not parse LocalPortString as integer")
	localAddress = net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort}

	_, err = fmt.Sscan(CallbackFrequencyMinutesString, &callbackFrequencyMinutes)
	utils.CheckErrorExit(utils.Error, err, utils.ERR_SCAN, "Could not parse CallbackFrequencyMinutesString as integer")
	callbackFrequencyMinutes = time.Duration(callbackFrequencyMinutes) * time.Minute

	_, err = fmt.Sscan(ServerPortString, &serverPort)
	utils.CheckErrorExit(utils.Error, err, utils.ERR_SCAN, "Could not parse ServerPortString as integer")
	serverAddress = net.TCPAddr{IP: net.ParseIP(ServerIP), Port: serverPort}

	agentInfo = AgentInfoStruct{AgentUUID: AgentUUID, LocalAddress: localAddress, ServerAddress: serverAddress, CallbackFrequency: callbackFrequencyMinutes, ServerPublicKey: serverPublicKey}

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
