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

/*
	Flags:
		--test:				Sets the server's listener to listen on localhost instead of the proper
							network interface IP address.
*/

import (
	//"crypto/tls"
	"bytes"
	"database/sql"
	"flag"
	"fmt"
	"html/template"
	"net/http"
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
	listenIP      string
)

// func createCert() {
// 	config := tls.Config{}
// 	fmt.Println(config)
// }

func serveLayoutTemplate(writer http.ResponseWriter, request *http.Request, functionName string, pageContent map[string]template.HTML) {
	layoutTemplateFilepath := utils.CurrentDirectory + "/site/templates/layout.html"
	layoutTemplate, err := template.ParseFiles(layoutTemplateFilepath)
	if utils.CheckWebError(writer, request, err, functionName+": Can't parse template", functionName) {
		return
	}

	// Serve templated HTML
	err = layoutTemplate.Execute(writer, pageContent)
	utils.CheckWebError(writer, request, err, functionName+": Couldn't execute template", functionName)
}

func returnTemplateHTML(writer http.ResponseWriter, request *http.Request, htmlFilename string, functionName string, pageContent map[string]template.HTML) template.HTML {
	contentTemplateFilepath := utils.CurrentDirectory + "/site/templates/" + htmlFilename
	contentTemplate, err := template.ParseFiles(contentTemplateFilepath)
	if utils.CheckWebError(writer, request, err, functionName+": Can't parse template", functionName) {
		return ""
	}

	// Construct templated HTML, store as a string
	var contentHTML bytes.Buffer
	err = contentTemplate.Execute(&contentHTML, pageContent)
	if utils.CheckWebError(writer, request, err, functionName+": Couldn't execute template", functionName) {
		return template.HTML(`<p style="color: red; font-weight: bold;">Error fetching page content</p>`)
	}

	if contentHTML.String() == "" {
		utils.Log(utils.Error, functionName+": Template returned no data")
		return template.HTML(`<p style="color: red; font-weight: bold;">Error fetching page content</p>`)
	}

	// Return templated HTML
	return template.HTML(contentHTML.String())
}

func handleDashboardPage(writer http.ResponseWriter, request *http.Request) {
	dashboardContent := map[string]template.HTML{"testString": "Hello, Dashboard!"}
	dashboardHTML := returnTemplateHTML(writer, request, "dashboard.html", "handleDashboardPage", dashboardContent)

	layoutContent := map[string]template.HTML{"title": "Red Team Dashboard", "pageContent": dashboardHTML}
	serveLayoutTemplate(writer, request, "handleDashboardPage", layoutContent)
}

func handleLoginPage(writer http.ResponseWriter, request *http.Request) {
	loginContent := map[string]template.HTML{"testString": "Hello, Login!"}
	loginHTML := returnTemplateHTML(writer, request, "login.html", "handleLoginPage", loginContent)

	layoutContent := map[string]template.HTML{"title": "Login", "pageContent": loginHTML}
	serveLayoutTemplate(writer, request, "handleLoginPage", layoutContent)
}

// JWT authentication middleware to authenticated pages and endpoints
func isAuthorized(endpoint func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header["Token"] == nil {
			fmt.Fprint(writer, "Not Authorized")
		} else {
			token, err := jwt.Parse(request.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("there was an error")
				}
				return jwtSigningKey, nil
			})

			if utils.CheckError(utils.Error, err, "Invalid JWT, could not parse") {
				fmt.Fprint(writer, err.Error())
			}

			// Allow access to page if token is valid
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
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix() // token expires after 30 minutes

	tokenString, err := token.SignedString(jwtSigningKey)

	return tokenString, err
}

func handleHomePage(writer http.ResponseWriter, request *http.Request) {
	// Generate the data we want to pass to the page-specific template
	jwt, err := generateJWT()
	if utils.CheckWebError(writer, request, err, "Could not sign JWT", "handleHomePage") {
		return
	}

	/* --- Scoreboard Table ---

			Sorted by descending point value.

			| Team Name | Points |
			----------------------
			| H4k0rz    | 150    |
			| Team 3    | 45     |
			| RedDead   | 7      |

			Information needed:
				Teams.team_id, Teams.name, AgentCheckins.agent_uuid, AgentCheckins.time_unix
				Last two checkin times for each Agent (by their agent_uuid)

	// ---old
	SELECT Agents.team_id, LastCheckins.agent_uuid, LastCheckins.time_unix, LastCheckins.value, LastCheckins.callback_order
	FROM (
		SELECT AgentCheckins.agent_uuid, AgentCheckins.time_unix, AgentCheckins.target_ipv4_address, TargetsInScope.value, row_number() OVER (PARTITION BY AgentCheckins.agent_uuid, TargetsInScope.target_ipv4_address ORDER BY time_unix DESC) AS callback_order
		FROM AgentCheckins
		JOIN TargetsInScope
		ON AgentCheckins.target_ipv4_address = TargetsInScope.target_ipv4_address
		ORDER BY AgentCheckins.agent_uuid, AgentCheckins.target_ipv4_address
	) AS LastCheckins
	JOIN Agents
	ON Agents.agent_uuid = LastCheckins.agent_uuid
	WHERE callback_order <= 2
	*/

	// getLastTwoCallbacksSQL := `
	// 	SELECT Agents.team_id, LastCheckins.agent_uuid, LastCheckins.time_unix, LastCheckins.value, LastCheckins.callback_order
	// 	FROM (
	// 		SELECT *
	// 		FROM (
	// 			SELECT AgentCheckins.agent_uuid, AgentCheckins.time_unix, AgentCheckins.target_ipv4_address, TargetsInScope.value, row_number() OVER (PARTITION BY AgentCheckins.agent_uuid, TargetsInScope.target_ipv4_address ORDER BY time_unix DESC) AS callback_order
	// 			FROM AgentCheckins
	// 			JOIN TargetsInScope
	// 			ON AgentCheckins.target_ipv4_address = TargetsInScope.target_ipv4_address
	// 			ORDER BY AgentCheckins.agent_uuid, AgentCheckins.target_ipv4_address
	// 		)
	// 		WHERE callback_order <= 2
	// 	) AS LastCheckins
	// 	JOIN Agents
	// 	ON Agents.agent_uuid = LastCheckins.agent_uuid
	// 	WHERE callback_order <= 2
	// `
	// getLastTwoCallbacksStatement, err := db.Prepare(getLastTwoCallbacksSQL)
	// if utils.CheckWebError(writer, request, err, "Could not create GetLastTwoCallbacks statement", "handleHomePage") {
	// 	return
	// }

	// rows, err := getLastTwoCallbacksStatement.Query()
	// if utils.CheckWebError(writer, request, err, "Could not execute GetLastTwoCallbacks statement", "handleHomePage") {
	// 	return
	// }

	// getTeamNameSQL := `
	// 	SELECT name
	// 	FROM Teams
	// 	WHERE team_id = ?
	// `
	// getTeamNameStatement, err := db.Prepare(getTeamNameSQL)
	// if utils.CheckWebError(writer, request, err, "Could not create GetTeamName statement", "handleHomePage") {
	// 	return
	// }

	// //teamCurrentPointSum := map[int]int{}
	// var dbTeamIDFirst int
	// var dbTeamNameFirst string
	// var dbAgentUUIDFirst string
	// var dbAgentCallbackUnixFirst int
	// for rows.Next() {
	// 	// team_id, agent_uuid, time_unix, value, callback_order (1 or 2, 1 being first)
	// 	// Compare second callback to the most recent one
	// 	var dbTeamIDSecond int
	// 	var dbTeamNameSecond string
	// 	var dbAgentUUIDSecond string
	// 	var dbAgentCallbackUnixSecond int

	// 	err = rows.Scan(&dbTeamIDSecond, &dbAgentUUIDSecond, &dbAgentCallbackUnixSecond)
	// 	if utils.CheckWebError(writer, request, err, "Could not scan GetLastTwoCallbacks rows", "handleHomePage") {
	// 		return
	// 	}

	// 	// Calculated time between most recent two callbacks from one agent
	// 	if dbAgentUUIDSecond == dbAgentUUIDFirst {
	// 		checkinTimeDifference := time.Second * time.Duration(dbAgentCallbackUnixFirst-dbAgentCallbackUnixSecond) //time.Duration(time.Now().Unix()-dbLastAgentCheckin) * time.Second
	// 		agentPoints := utils.CalculateCallbackPoints(checkinTimeDifference)
	// 	}

	// 	err = getTeamNameStatement.QueryRow(dbTeamID).Scan(&dbTeamName)
	// 	if utils.CheckWebError(writer, request, err, "Could not execute GetTeamName statement", "handleHomePage") {
	// 		return
	// 	}

	// 	dbTeamIDFirst = dbTeamIDSecond
	// 	dbTeamNameFirst = dbTeamNameSecond
	// 	dbAgentUUIDFirst = dbAgentUUIDSecond
	// 	dbAgentCallbackUnixFirst = dbAgentCallbackUnixSecond

	// }

	// // Let go of db lock
	// checkSourceIPInScopeStatement.Close()

	// The parameters to fill the page-specific template
	homeContent := map[string]template.HTML{"jwt": template.HTML(jwt)}
	// The templated HTML of type template.HTML for proper rendering on the DOM
	homeHTML := returnTemplateHTML(writer, request, "index.html", "handleHomePage", homeContent)

	// Must use template.HTML for proper DOM rendering, otherwise it will look like plain text
	layoutContent := map[string]template.HTML{"title": "Scoreboard", "pageContent": homeHTML}
	// Fill the layout with our page-specific templated HTML
	// The layout template automatically includes the header info, navbar, and general layout
	serveLayoutTemplate(writer, request, "handleHomePage", layoutContent)
}

/* --- Page handler outline ---
1. Generate whatever data is needed for input parameters to the HTML templates.
2. Create parameters mapping for page-specific template.
3. Fill the page-specific template.
4. Create parameters mapping for layout template, including your page-specific templated HTML.
5. Serve to the user the full templated layout page.
*/

func handleRequests() {
	// TODO: Add request logging
	http.HandleFunc("/", handleHomePage)
	http.HandleFunc("/login", handleLoginPage)
	http.HandleFunc("/dashboard", handleDashboardPage)
	//http.Handle("/dashboard", isAuthorized(handleDashboardPage))
}

func main() {
	//utils.Log(utils.Warning, "--- If you have not already done so, please run the server before running this ---")
	var argTest bool
	flag.BoolVar(&argTest, "test", false, "Listen on localhost instead of the default interface's IP address")
	flag.Parse()

	db = utils.GetDatabaseHandle() // `=` instead of `:=` to set the global variable
	utils.ValidateDatabase(db)
	defer utils.Close(db)

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
	if argTest {
		listenIP = "127.0.0.1"
	} else {
		listenIP = utils.GetOutboundIP().String()
	}

	listenAddress := listenIP + listenPort

	utils.Log(utils.Done, "Running HTTPS server at", listenAddress)

	// https://pkg.go.dev/net/http#FileServer
	// Allow the hosting of static files like our images and stylesheets
	staticFileServer := http.FileServer(http.Dir(utils.CurrentDirectory + "/site/root/static"))
	http.Handle("/static/", http.StripPrefix("/static/", staticFileServer))

	// Register page handlers
	handleRequests()

	err := http.ListenAndServeTLS(listenAddress, certPath, privateKeyPath, nil)
	utils.CheckErrorExit(utils.Error, err, utils.ERR_GENERIC, "Couldn't start HTTP listener at", listenAddress)
}
