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
- Use the W3C validator
*/

/*
	Flags:
		--test:				Sets the server's listener to listen on localhost instead of the proper
							network interface IP address.
		--port:				Port to listen on.
*/

import (
	//"crypto/tls"
	"bytes"
	"database/sql"
	"flag"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"time"

	"github.com/s-christian/pwnts/utils"

	"github.com/golang-jwt/jwt"
	_ "github.com/mattn/go-sqlite3"
)

const (
	maxCallbackTime time.Duration = time.Minute * 15
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

func returnTemplateHTML(writer http.ResponseWriter, request *http.Request, htmlFilename string, functionName string, pageContent map[string]interface{}) template.HTML {
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
	dashboardContent := map[string]interface{}{"testString": "Hello, Dashboard!"}
	dashboardHTML := returnTemplateHTML(writer, request, "dashboard.html", "handleDashboardPage", dashboardContent)

	layoutContent := map[string]template.HTML{"title": "Red Team Dashboard", "pageContent": dashboardHTML}
	serveLayoutTemplate(writer, request, "handleDashboardPage", layoutContent)
}

func handleLoginPage(writer http.ResponseWriter, request *http.Request) {
	loginContent := map[string]interface{}{"testString": "Hello, Login!"}
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
	/*
		--- Retrieve the last two Agent checkins grouped by team and target IP address ---
	*/
	getLastTwoCallbacksSQL := `
		SELECT Teams.name, Callbacks.target_ipv4_address, Callbacks.value, Callbacks.time_unix, Callbacks.callback_order
		FROM (
			SELECT Agents.team_id, Callbacks.target_ipv4_address, Callbacks.value, Callbacks.time_unix, Callbacks.agent_uuid, row_number() OVER (PARTITION BY Agents.team_id, Callbacks.target_ipv4_address ORDER BY Callbacks.time_unix DESC) AS callback_order
			FROM (
				SELECT AgentCheckins.target_ipv4_address, TargetsInScope.value, AgentCheckins.time_unix, AgentCheckins.agent_uuid
				FROM AgentCheckins
				JOIN TargetsInScope
				ON AgentCheckins.target_ipv4_address = TargetsInScope.target_ipv4_address
			) AS Callbacks
			JOIN Agents
			ON Callbacks.agent_uuid = Agents.agent_uuid
		) AS Callbacks
		JOIN Teams
		ON Callbacks.team_id = Teams.team_id
		WHERE callback_order <= 2
	`
	getLastTwoCallbacksStatement, err := db.Prepare(getLastTwoCallbacksSQL)
	if utils.CheckWebError(writer, request, err, "Could not create GetLastTwoCallbacks statement", "handleHomePage") {
		return
	}

	lastTwoCallbacksRows, err := getLastTwoCallbacksStatement.Query()
	if utils.CheckWebError(writer, request, err, "Could not execute GetLastTwoCallbacks statement", "handleHomePage") {
		return
	}
	utils.Close(getLastTwoCallbacksStatement)

	/*
		--- Retrieve all team names and initialize the map ---
	*/
	getTeamNamesSQL := `
		SELECT name
		FROM Teams
	`
	getTeamNamesStatement, err := db.Prepare(getTeamNamesSQL)
	if utils.CheckWebError(writer, request, err, "Could not create GetTeamName statement", "handleHomePage") {
		return
	}

	teamNamesRows, err := getTeamNamesStatement.Query()
	if utils.CheckWebError(writer, request, err, "Could not execute GetTeamNames statement", "handleHomePage") {
		return
	}
	utils.Close(getTeamNamesStatement)

	teamsPointsAndHosts := make(map[string][]int)
	for teamNamesRows.Next() {
		if utils.CheckWebError(writer, request, lastTwoCallbacksRows.Err(), "Could not prepare next db row for scanning GetTeamNames rows", "handleHomePage") {
			return
		}

		var dbTeamName string

		err = teamNamesRows.Scan(&dbTeamName)
		if utils.CheckWebError(writer, request, err, "Could not scan GetTeamNames rows", "handleHomePage") {
			return
		}

		// Initialize the pwnts and pwns per team to 0
		teamsPointsAndHosts[dbTeamName] = []int{0, 0}
	}
	utils.Close(teamNamesRows)

	// Scoring note:
	// Multiple Agents from the same team on the same host is fine.
	// We only use the last checkins, grouped by team and IP.
	var (
		dbTeamNameLast          string
		dbTargetValueLast       int
		dbAgentCallbackUnixLast int
		agentDead               bool = false
		singleCallback          bool = false
	)
	for lastTwoCallbacksRows.Next() {
		if utils.CheckWebError(writer, request, lastTwoCallbacksRows.Err(), "Could not prepare next db row for scanning GetLastTwoCallbacks rows", "handleHomePage") {
			return
		}

		// team_id, target_ip_address, value, time_unix, callback_order (1 or 2, 1 being first)
		// Compare second callback to the most recent one
		var (
			dbTeamNameCurrent          string
			dbTargetIpAddressCurrent   string
			dbTargetValueCurrent       int
			dbAgentCallbackUnixCurrent int
			dbCallbackOrderCurrent     int
		)

		err = lastTwoCallbacksRows.Scan(&dbTeamNameCurrent, &dbTargetIpAddressCurrent, &dbTargetValueCurrent, &dbAgentCallbackUnixCurrent, &dbCallbackOrderCurrent)
		if utils.CheckWebError(writer, request, err, "Could not scan GetLastTwoCallbacks rows", "handleHomePage") {
			return
		}

		//fmt.Printf("%d | %s | %d | %d | %d\n", dbTeamIDCurrent, dbTargetIpAddressCurrent, dbTargetValueCurrent, dbAgentCallbackUnixCurrent, dbCallbackOrderCurrent)

		if dbCallbackOrderCurrent == 1 {
			var checkinTimeAgo time.Duration = time.Duration(time.Now().Unix()-int64(dbAgentCallbackUnixCurrent)) * time.Second
			if checkinTimeAgo.Round(time.Second) > maxCallbackTime {
				agentDead = true
				continue // last callback was too long ago, assume Agent is dead
			}
			agentDead = false

			if singleCallback { // last row only had a single callback (the "pair" ended with callbackOrder == 1), add its points
				teamsPointsAndHosts[dbTeamNameLast][0] += dbTargetValueLast // a single (Agent's first) callback will initially receive the full target value
				teamsPointsAndHosts[dbTeamNameLast][1]++                    // increment num of pwned hosts
				continue
			}

			dbTeamNameLast = dbTeamNameCurrent
			dbTargetValueLast = dbTargetValueCurrent
			dbAgentCallbackUnixLast = dbAgentCallbackUnixCurrent
			singleCallback = true // set for next iteration
		} else if dbCallbackOrderCurrent == 2 {
			singleCallback = false
			if agentDead { // skip callback pair for dead Agents
				continue
			}

			checkinTimeDifference := time.Second * time.Duration(dbAgentCallbackUnixLast-dbAgentCallbackUnixCurrent)
			teamsPointsAndHosts[dbTeamNameCurrent][0] += utils.CalculateCallbackPoints(checkinTimeDifference, dbTargetValueCurrent)
			teamsPointsAndHosts[dbTeamNameCurrent][1]++ // increment num of pwned hosts
		} else {
			fmt.Println("I have no idea what happened:", dbCallbackOrderCurrent)
		}
	}
	utils.Close(lastTwoCallbacksRows)

	if singleCallback { // account for the very last row being a single callback
		teamsPointsAndHosts[dbTeamNameLast][0] += dbTargetValueLast // a single (Agent's first) callback will initially receive the full target value
		teamsPointsAndHosts[dbTeamNameLast][1]++                    // increment num of pwned hosts
	}

	// The parameters to fill the page-specific template
	homeContent := map[string]interface{}{"scoreboardData": teamsPointsAndHosts}
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
	var argPort int
	flag.BoolVar(&argTest, "test", false, "Listen on localhost instead of the default interface's IP address")
	flag.IntVar(&argPort, "port", 443, "Port to listen on")
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
	var listenIP net.IP
	if argTest {
		listenIP = net.ParseIP("127.0.0.1")
	} else {
		listenIP = utils.GetOutboundIP()
	}

	listenAddress := fmt.Sprintf("%s:%d", listenIP.String(), argPort)

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
