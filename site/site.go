package main

/* TODO
- Build a virtual machine on CyberOps4 for testing and serving Pwnts
	- Install a NEW VM
	- Build another VM to test agent callbacks
		- "Can build as many VMs as you feel the urge to build"
	- Document all steps
- Dockerize
	- Document all Docker stuff
	- Serve web server within Docker
- Front-end language
*/

import (
	//"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os"
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

func main() {
	// we want to validate the db with our checks from server.go before running site.go
	utils.Log(utils.Warning, "--- If you have not already done so, please run the server before running this ---")

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
	defer utils.CloseDatabase(db)

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
