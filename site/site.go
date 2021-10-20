package main

/*
	Flags:
		--register-targets:	Add targets by their IP address and point value. Targets are defined
							in the file "targets.txt" in the CSV format "ip,point_value".
*/

import (
	"bufio"
	//"crypto/tls"
	"database/sql"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/s-christian/pwnts/utils"

	"github.com/golang-jwt/jwt"
	_ "github.com/mattn/go-sqlite3"
)

const (
	listenPort string = ":443"
)

// In production don't commit or make public your jwtSigningKey
// Here's a safer way by setting the MY_JWT_TOKEN environment variable:
// var jwtSigningKey = os.Get("MY_JWT_TOKEN")
var (
	db            *sql.DB
	jwtSigningKey []byte = []byte("verysecret")
)

// func createCert() {
// 	config := tls.Config{}
// 	fmt.Println(config)
// }

// JWT authentication middleware to authenticated API endpoints
func isAuthorized(endpoint func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header["Token"] == nil {
			fmt.Fprint(writer, "Not Authorized")
		} else {
			token, err := jwt.Parse(request.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return jwtSigningKey, nil
			})

			if utils.CheckError(utils.Error, err, "Invalid JWT, could not parse") {
				fmt.Fprint(writer, err.Error())
			}

			if token.Valid {
				endpoint(writer, request)
			}
		}
	})
}

func generateJWT() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["user"] = "John Smith"
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(jwtSigningKey)

	return tokenString, err
}

func homePage(writer http.ResponseWriter, request *http.Request) {
	jwtToken, err := generateJWT()
	if utils.CheckError(utils.Error, err, "Could not sign JWT") {
		_, err = fmt.Fprint(writer, err.Error())
		utils.CheckError(utils.Error, err, "homePage: Couldn't write to http.ResponseWriter")
	} else {
		_, err = fmt.Fprint(writer, jwtToken)
		utils.CheckError(utils.Error, err, "homePage: Couldn't write to http.ResponseWriter")
	}
}

func handleRequests() {
	http.Handle("/", isAuthorized(homePage))
}

func registerAgent(agentUUID string, teamID int, serverPrivateKey string, agentPublicKey string, createdDate int, rootDate int) {
	utils.Log(utils.Info, "Registering Agent", agentUUID)

	addAgentSQL := `
		INSERT INTO Agents(agent_uuid, team_id, server_private_key, agent_public_key, created_date_unix, root_date_unix)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	addAgentStatement, err := db.Prepare(addAgentSQL)
	if utils.CheckError(utils.Error, err, "\tCould not create AddTarget statement") {
		return
	}
	defer addAgentStatement.Close()

	_, err = addAgentStatement.Exec(agentUUID, teamID, serverPrivateKey, agentPublicKey, createdDate, rootDate)
	if utils.CheckError(utils.Warning, err, "\tCould not register Agent") {
		return
	}

	// Count total Agents
	agentsCount := db.QueryRow("SELECT COUNT(*) FROM Agents")
	var numAgents int
	agentsCount.Scan(&numAgents)

	utils.Log(utils.Done, "\tRegistered Agent", agentUUID)
	utils.Log(utils.Done, "\tThere are now a total of", fmt.Sprint(numAgents), "registered Agents")
}

// Flag: --register-targets
func registerTargetsFromFile(filename string) {
	utils.Log(utils.Info, "Registering targets:")

	fullFilePath := utils.CurrentDirectory + filename
	targetsFile, err := os.Open(fullFilePath)
	utils.CheckErrorExit(utils.Error, err, utils.ERR_GENERIC, "Cannot open file '"+fullFilePath+"'")
	defer targetsFile.Close()

	addTargetSQL := `
		INSERT INTO TargetsInScope(target_ipv4_address, value)
		VALUES (?, ?)
	`
	addTargetStatement, err := db.Prepare(addTargetSQL)
	utils.CheckErrorExit(utils.Error, err, utils.ERR_GENERIC, "Could not create AddTarget statement")
	defer addTargetStatement.Close()

	scanner := bufio.NewScanner(targetsFile)
	addedCounter, lineCounter := 0, 0
	for scanner.Scan() {
		lineCounter++
		lineCSV := strings.Split(scanner.Text(), ",")

		var targetIP string = lineCSV[0]
		var targetValue int
		fmt.Sscan(lineCSV[1], &targetValue)

		utils.Log(utils.List, "Target IP: "+targetIP+",\tValue: "+fmt.Sprint(targetValue))

		_, err := addTargetStatement.Exec(targetIP, targetValue)

		if utils.CheckError(utils.Warning, err, "\tCould not add target (already exists?)") {
			continue
		}

		utils.Log(utils.Done, "\tAdded")

		addedCounter++
	}

	targetsCount := db.QueryRow("SELECT COUNT(*) FROM TargetsInScope")
	var numTargets int
	targetsCount.Scan(&numTargets)

	utils.Log(utils.Done, "Registered", fmt.Sprintf("%d/%d", addedCounter, lineCounter), "targets")
	utils.Log(utils.Done, "There are now a total of", fmt.Sprint(numTargets), "targets in scope")
}

func main() {
	// we want to validate the db with our checks from server.go before running site.go
	utils.Log(utils.Warning, "--- If you have not already done so, please run the server before running this ---")

	// Flags can be used with '--name' or '-name', doesn't matter.
	var argRegisterTargetsFromFile string
	flag.StringVar(&argRegisterTargetsFromFile, "register-targets", "", "Add targets by their IP address and point value. By default, targets are defined in the file \"/server/targets.txt\" in the CSV format \"ip,point_value\".")
	flag.Parse()

	// Open database
	var err error                                         // must explicitly declare this variable ot be able to use "=" instead of ":=" in the below sql.Open statement.
	db, err = sql.Open("sqlite3", utils.DatabaseFilepath) // "=" required instead of ":=" as to not declare a local `db` variable
	utils.CheckErrorExit(utils.Error, err, utils.ERR_GENERIC, "Could not open sqlite database file \""+utils.DatabaseFilename+"\"")
	if db == nil {
		utils.Log(utils.Error, "db == nil, this should never happen")
		os.Exit(utils.ERR_DATABASE_INVALID)
	} else {
		utils.Log(utils.Info, "Opened database file")
	}
	defer db.Close()

	// Optionally register targets from the file "server/targets.txt"
	// Flag: --register-targets
	if argRegisterTargetsFromFile != "" {
		registerTargetsFromFile(argRegisterTargetsFromFile)
		os.Exit(0)
	}

	// TODO: remove this temporary agentUUID used for testing purposes
	agentUUID := "76b8a692-f7be-4f51-b72a-86244a66e680"
	registerAgent(agentUUID, 1, "", "", int(time.Now().Unix()), 0)

	// cert, err := tls.LoadX509KeyPair(utils.CurrentDirectory+"/pwnts.red.pem", utils.CurrentDirectory+"/pwnts_server_key.pem")
	// if err != nil {
	// 	utils.Log(utils.Error, "Couldn't load X509 keypair")
	// 	os.Exit(1)
	// }

	// tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	// listener, err := tls.Listen("tcp", listenPort, &tlsConfig)
	// if err != nil {
	// 	utils.Log(utils.Error, "Couldn't set up listener")
	// 	os.Exit(1)
	// }
	// defer listener.Close()

	certPath := utils.CurrentDirectory + "/pwnts_red.pem"
	privateKeyPath := utils.CurrentDirectory + "/pwnts_server_key.pem"

	// cert, err := os.ReadFile(certPath)
	// utils.CheckErrorExit(utils.Error, err, utils.ERR_GENERIC, "Cannot read certificate file '"+certPath+"'")
	// privateKey, err := os.ReadFile(privateKeyPath)
	// utils.CheckErrorExit(utils.Error, err, utils.ERR_GENERIC, "Cannot read private key file '"+privateKeyPath+"'")

	/*
		--- Main site ---
	*/
	utils.Log(utils.Done, "Starting HTTP server on port "+listenPort)

	handleRequests()

	address := "localhost" + listenPort
	err = http.ListenAndServeTLS(address, certPath, privateKeyPath, nil)
	utils.CheckErrorExit(utils.Error, err, utils.ERR_GENERIC, "Couldn't start HTTP listener at", address)
}
