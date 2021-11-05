package main

/* TODO
- Build a virtual machine on CyberOps4 for testing and serving Pwnts
	- Install a NEW VM
	- Build another VM to test agent callbacks
		- "Can build as many VMs as you feel the urge to build"
	- Document all steps
- Use the W3C validator
*/

/*
	Flags:
		--test:				Sets the server's listener to listen on localhost instead of the proper
							network interface IP address.
		--port:				Port to listen on.
*/

import (
	"bytes"
	//"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
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
	switch request.Method {
	// GET: Display login form
	case http.MethodGet:
		loginContent := map[string]interface{}{}
		loginHTML := returnTemplateHTML(writer, request, "login.html", "handleLoginPage", loginContent)

		layoutContent := map[string]template.HTML{"title": "Login", "pageContent": loginHTML}
		serveLayoutTemplate(writer, request, "handleLoginPage", layoutContent)

	// POST: API to set the JWT cookie upon successful login and return success
	case http.MethodPost:
		// Necessary to populate the request.Form and request.PostForm attributes
		request.ParseMultipartForm(1024)

		// PostForm is of type url.Values which is of type map[string][]string
		postedUsername := request.PostForm["username"][0]
		postedPassword := request.PostForm["password"][0]

		// https://pkg.go.dev/encoding/json#Marshal
		type ReturnMessage struct {
			Message string `json:"message"`
			Error   string `json:"error",omitempty`
		}

		// loginResponse := ReturnMessage{}
		jsonEncoder := json.NewEncoder(writer)

		// Checking for empty form data should also be done on the client side with JavaScript
		if postedUsername == "" || postedPassword == "" {
			// Craft struct to return as JSON
			// loginResponse.Error = "Please supply values for username and password"

			// Send JSON back
			writer.WriteHeader(http.StatusBadRequest) // set status code to 400: Bad Request
			// err := jsonEncoder.Encode(loginResponse)
			err := jsonEncoder.Encode(&ReturnMessage{Error: "Please supply values for username and password"})

			// Check for encoding error
			utils.CheckWebError(writer, request, err, "Could not encode login response to JSON", "handleLoginPage")

			return
		}

		// Testing
		//fmt.Fprintf(writer, "--- Received ---\nUsername: %s\nPassword: %s", postedUsername, postedPassword)

		validLogin, err := utils.ValidateLogin(db, postedUsername, postedPassword)
		if utils.CheckWebError(writer, request, err, "Error while validating user login", "handleLoginPage") {
			return
		}

		// Invalid login: passwords do not match
		if !validLogin {
			// loginResponse.Error = "Invalid login"

			// Send JSON back
			writer.WriteHeader(http.StatusBadRequest) // set status code to 400: Bad Request
			err := jsonEncoder.Encode(&ReturnMessage{Error: "Invalid login"})
			//err := jsonEncoder.Encode(loginResponse)

			// Check for encoding error
			utils.CheckWebError(writer, request, err, "Could not encode login response to JSON", "handleLoginPage")

			return
		}

		// Else, it must have been a valid login
		// loginResponse.Message = "Authenticated!"

		err = jsonEncoder.Encode(&ReturnMessage{Message: "Authenticated!"})
		// err = jsonEncoder.Encode(loginResponse)
		utils.CheckWebError(writer, request, err, "Could not encode login response to JSON", "handleLoginPage")
	}
}

// JWT authentication middleware to authenticated pages and endpoints
func isAuthorized(endpoint func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			authCookie, err := request.Cookie("auth")
			if err != nil {
				//fmt.Fprint(writer, "Not authorized")
				http.Redirect(writer, request, "/login", http.StatusFound)
				return
			} else {
				token, err := jwt.Parse(
					authCookie.Value,
					func(token *jwt.Token) (interface{}, error) {
						if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
							//fmt.Fprint(writer, "Not authorized")
							http.Redirect(writer, request, "/login", http.StatusFound)
							return nil, errors.New("error parsing jwt: incorrect signing method")
						}

						// Return the signing key for token validation
						return jwtSigningKey, nil
					},
				)

				// Token is not not a proper JWT
				if utils.CheckError(utils.Warning, err, "Could not parse JWT for authentication") {
					//fmt.Fprint(writer, "Not authorized")
					http.Redirect(writer, request, "/login", http.StatusFound)
					return
				}

				// Check if token is otherwise valid
				if !token.Valid {
					//fmt.Fprint(writer, "JWT token is invalid, cannot authenticate")
					http.Redirect(writer, request, "/login", http.StatusFound)
					return
				}

				// Validate token claims (the payload data)
				tokenClaims := token.Claims.(jwt.MapClaims)

				if tokenClaims["user"] == nil || tokenClaims["teamId"] == nil {
					//fmt.Fprint(writer, "Not authorized, invalid token")
					http.Redirect(writer, request, "/login", http.StatusFound)
					return
				}

				var tokenUser string
				var tokenTeamID int
				tokenUser = tokenClaims["user"].(string)
				fmt.Sscan(tokenClaims["teamId"].(string), &tokenTeamID)

				// Make sure the token isn't expired (current time > exp).
				// Automatically uses the standard "exp" claim, a timestamp in UNIX seconds.
				if tokenClaims.Valid() != nil {
					//fmt.Fprint(writer, "Token has expired, please log in again")
					http.Redirect(writer, request, "/login", http.StatusFound)
					return
				}

				// Validate our custom claims data
				if tokenUser == "" {
					//fmt.Fprint(writer, "Not authorized, invalid user")
					http.Redirect(writer, request, "/login", http.StatusFound)
					return
				}
				if tokenTeamID < 1 {
					//fmt.Fprint(writer, "Not authorized, invalid teamId")
					http.Redirect(writer, request, "/login", http.StatusFound)
					return
				}

				// If everything was successful, navigate to the page
				endpoint(writer, request)
			}
		},
	)
}

func generateJWT(username string, teamID int) (string, error) {
	/*
		--- Token Payload (Claims) ---
		"user": <team_name>,
		"teamId": <team_id>,
		"exp": <timestamp_unix_seconds>

		JWT is stored as a cookie with the name "auth"
	*/

	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["user"] = username
	claims["teamId"] = teamID
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
	teamNames, err := utils.GetTeamNames(db)
	if utils.CheckWebError(writer, request, err, "Could not retrieve list of Team names", "handleHomePage") {
		return
	}

	teamsPointsAndHosts := map[string][]int{}
	for _, teamName := range teamNames {
		teamsPointsAndHosts[teamName] = []int{0, 0}
	}

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
	http.Handle("/dashboard", isAuthorized(handleDashboardPage))
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
