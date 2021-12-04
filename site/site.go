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
	"strings"

	//"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os/exec"

	"github.com/google/uuid"

	"github.com/s-christian/pwnts/site/api"
	"github.com/s-christian/pwnts/utils"

	_ "github.com/mattn/go-sqlite3"
)

// var jwtSigningKey = os.Get("MY_JWT_TOKEN")
// TODO: Read from a `.env` file or similar
var (
	db *sql.DB
)

func serveLayoutTemplate(writer http.ResponseWriter, request *http.Request, functionName string, pageContent map[string]template.HTML) {
	layoutTemplateFilepath := utils.CurrentDirectory + "/site/templates/layout.html"
	layoutTemplate, err := template.ParseFiles(layoutTemplateFilepath)
	if utils.CheckWebError(writer, request, err, functionName+": Can't parse template") {
		return
	}

	// Serve templated HTML
	err = layoutTemplate.Execute(writer, pageContent)
	utils.CheckWebError(writer, request, err, functionName+": Couldn't execute template")
}

func returnTemplateHTML(writer http.ResponseWriter, request *http.Request, htmlFilename string, functionName string, pageContent map[string]interface{}) template.HTML {
	contentTemplateFilepath := utils.CurrentDirectory + "/site/templates/" + htmlFilename
	contentTemplate, err := template.ParseFiles(contentTemplateFilepath)
	if utils.CheckWebError(writer, request, err, functionName+": Can't parse template '"+htmlFilename+"'") {
		return template.HTML(`<p style="color: red; font-weight: bold;">Error constructing page content</p>`)
	}

	// Construct templated HTML, store as a string
	var contentHTML bytes.Buffer
	err = contentTemplate.Execute(&contentHTML, pageContent)
	if utils.CheckWebError(writer, request, err, functionName+": Couldn't execute template '"+htmlFilename+"'") {
		return template.HTML(`<p style="color: red; font-weight: bold;">Error fetching page content</p>`)
	}

	if contentHTML.String() == "" {
		utils.Log(utils.Error, functionName+": Template returned no data")
		return template.HTML(`<p style="color: red; font-weight: bold;">Error serving page content</p>`)
	}

	// Return templated HTML
	return template.HTML(contentHTML.String())
}

func handleDashboardPage(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	// *** GET: Display team dashboard with agent generation
	case http.MethodGet:
		dashboardContent := map[string]interface{}{"teamName": "Sample Team Name"}
		dashboardHTML := returnTemplateHTML(writer, request, "dashboard.html", "handleDashboardPage", dashboardContent)

		layoutContent := map[string]template.HTML{"title": "Red Team Dashboard", "pageContent": dashboardHTML}
		serveLayoutTemplate(writer, request, "handleDashboardPage", layoutContent)

	// *** POST: Generate agent and provide downloadable agent executable
	case http.MethodPost:
		/*
			Required parameters for agent construction in `pwnts/agent/agent.go`:
			- Agent variables:
				- agentUUID
				- localPort
				- serverIP
				- serverPort
				- callbackFrequencyMinutes
			- Environment variables:
				- GOOS   (the OS to target)
				- GOARCH (the architecture to target)
		*/

		agentUUID := uuid.New()
		postedLocalPort := utils.GetFormDataSingle(writer, request, "localPort")
		postedCallbackFrequencyMinutes := utils.GetFormDataSingle(writer, request, "callbackMins")
		postedOS := utils.GetFormDataSingle(writer, request, "targetOs")
		postedArch := utils.GetFormDataSingle(writer, request, "targetArch")

		/* --- Logic --- */
		// Check for the existence of necessary values
		if postedLocalPort == "" || postedCallbackFrequencyMinutes == "" || postedOS == "" {
			utils.ReturnStatusUserError(writer, request, "Please provide values for all inputs")
			utils.LogIP(utils.Error, request, "Invalid input value(s), request was modified")
			return
		}

		// Check for invalid values

		// Give types to the integer values
		var localPort int
		var callbackFrequencyMinutes int
		_, err := fmt.Sscan(postedLocalPort, &localPort)
		if err != nil {
			utils.ReturnStatusUserError(writer, request, "Please provide integer inputs")
			utils.LogIP(utils.Error, request, "Invalid input value(s), request was modified")
			return
		}
		_, err = fmt.Sscan(postedCallbackFrequencyMinutes, &callbackFrequencyMinutes)
		if err != nil {
			utils.ReturnStatusUserError(writer, request, "Please provide integer inputs")
			utils.LogIP(utils.Error, request, "Invalid input value(s), request was modified")
			return
		}

		if callbackFrequencyMinutes < 1 || callbackFrequencyMinutes > 15 ||
			localPort < 1 || localPort > 65535 ||
			(postedOS != "windows" && postedOS != "linux") ||
			(postedArch != "amd64" && postedArch != "386") {

			utils.ReturnStatusUserError(writer, request, "Invalid input detected")
			utils.LogIP(utils.Error, request, "Invalid input value(s), request was modified")
			return
		}

		// Generate the Agent
		agentSource := utils.CurrentDirectory + "/agent/agent.go"

		newAgentFilename := "agent_" + postedOS + "_" + postedArch + "_" + agentUUID.String()
		newAgentFilenameTruncated := strings.Join(strings.Split(newAgentFilename, "_")[0:3], "_")
		if postedOS == "windows" {
			newAgentFilename = newAgentFilename + ".exe"
			newAgentFilenameTruncated = newAgentFilenameTruncated + ".exe"
		}

		buildDirectory := utils.CurrentDirectory + "/agent/compiled_agents/"

		commandString := fmt.Sprintf(
			"GOOS=%s GOARCH=%s go build -trimpath -ldflags '-s -w' -o %s %s",
			postedOS,
			postedArch,
			buildDirectory+newAgentFilename,
			agentSource,
		)

		// TODO: This currently only works on Linux. In the future, determine
		// the host OS and either run "cmd" or "sh" accordingly.
		err = exec.Command("sh", "-c", commandString).Run()
		if err != nil {
			utils.ReturnStatusUserError(writer, request, "Error compiling agent. Please contact an admin.")
			utils.LogError(utils.Error, err, utils.GetUserIP(request)+": Error compiling agent")
			return
		}

		// Prompt the user's browser to download the file, stripping the UUID
		// from the filename.
		utils.PromptFileDownload(writer, request, buildDirectory+newAgentFilename, newAgentFilenameTruncated)

		//utils.ReturnStatusSuccess(writer, request, "Compiled agent successfully!")
	}

}

func handleLoginPage(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	// *** GET: Display login form
	case http.MethodGet:
		loginContent := map[string]interface{}{}
		loginHTML := returnTemplateHTML(writer, request, "login.html", "handleLoginPage", loginContent)

		layoutContent := map[string]template.HTML{"title": "Login", "pageContent": loginHTML}
		serveLayoutTemplate(writer, request, "handleLoginPage", layoutContent)

	// *** POST: API to set the JWT cookie upon successful login and return success
	case http.MethodPost:
		postedUsername := utils.GetFormDataSingle(writer, request, "username")
		postedPassword := utils.GetFormDataSingle(writer, request, "password")

		// --- Logic ---
		// Checking for empty form data should also be done on the client side
		// with JavaScript. This is just a fallback.
		if postedUsername == "" || postedPassword == "" {
			utils.ReturnStatusUserError(writer, request, "Please supply values for username and password")
			return
		}

		teamId, _, passwordHash, _, err := utils.GetUserInfo(db, postedUsername)
		if err == sql.ErrNoRows {
			utils.ReturnStatusUserError(writer, request, "Invalid login")
			return
		} else if utils.CheckError(utils.Error, err, "Backend error querying database") {
			utils.ReturnStatusUserError(writer, request, "Could not query database. Please contact an administrator.")
			return
		}

		validLogin := utils.ValidatePasswordHash(postedPassword, passwordHash)

		// Invalid login: user does not exist or passwords do not match
		if !validLogin {
			utils.ReturnStatusUserError(writer, request, "Invalid login")
			return
		}

		// Else, it is a valid login, so continue

		// Set "auth" cookie to a signed JWT
		newToken, err := utils.GenerateJWT(db, postedUsername, teamId)
		if utils.CheckError(utils.Error, err, "Could not generate JWT for valid user") {
			utils.ReturnStatusServerError(writer, request, "Could not generate a JWT. Please contact an administrator.")
			return
		}

		// At the end, redirect user to their eeam page
		//defer http.Redirect(writer, request, "/dashboard", http.StatusFound)
		// HTTP POST won't redirect. This has been done in client-side JavaScript instead.

		authCookie := http.Cookie{Name: "auth", Value: newToken, Secure: true} //, HttpOnly: true}
		http.SetCookie(writer, &authCookie)

		utils.ReturnStatusSuccess(writer, request, "Greetings, hacker!")
		utils.LogIP(utils.Done, request, "User '"+postedUsername+"' successfully logged in")
	}
}

// JWT authentication middleware to authenticated pages and endpoints
func isAuthorized(endpoint func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			tokenClaims, err := utils.GetAuthClaims(writer, request)
			if err != nil {
				utils.ClearAuthCookieAndRedirect(writer, request, err)
				return
			}

			// Ensure the claims we need exist in the first place
			if tokenClaims["user"] == nil || tokenClaims["teamId"] == nil {
				utils.ClearAuthCookieAndRedirect(writer, request, errors.New("token claims don't exist"))
				return
			}

			// Give the claims a Go type
			var tokenUser string = tokenClaims["user"].(string)
			// Go's JSON unmarshalling decodes JSON numbers to type float64
			var tokenTeamID int = int(tokenClaims["teamId"].(float64))

			// Validate the claims
			if tokenUser == "" {
				utils.ClearAuthCookieAndRedirect(writer, request, errors.New("token claim 'user' is invalid"))
				return
			}
			if tokenTeamID < 1 {
				utils.ClearAuthCookieAndRedirect(writer, request, errors.New("token claim 'teamId' is invalid"))
				return
			}

			// If everything was successful, navigate to the page
			endpoint(writer, request)
		},
	)
}

func handleHomePage(writer http.ResponseWriter, request *http.Request) {
	/*
		Client-side JavaScript will continually update the scoreboard via AJAX,
		but the first page load populates the scoreboard for the user.
		This was mainly me just learning Go JSON marshaling, not too practical.
	*/
	var teamsPointsAndHosts map[string]api.TeamScores
	var homeContent map[string]interface{}

	scoreboardData, err := api.GetScoreboardData(db)

	if err == nil {
		err = json.Unmarshal(scoreboardData, &teamsPointsAndHosts) // convert data back into Go map
		if !utils.CheckError(utils.Error, err, "Could not unmarshal scoreboard data from JSON") {
			// The parameters to fill the page-specific template
			homeContent = map[string]interface{}{"scoreboardData": teamsPointsAndHosts}
		}
	}

	// The templated HTML of type template.HTML for proper rendering on the DOM
	homeHTML := returnTemplateHTML(writer, request, "index.html", "handleHomePage", homeContent)

	// Must use template.HTML for proper DOM rendering, otherwise it will be plain text
	layoutContent := map[string]template.HTML{"title": "Scoreboard", "pageContent": homeHTML}
	// Fill the layout with our page-specific templated HTML
	// The layout template automatically includes the header info, navbar, and general layout
	serveLayoutTemplate(writer, request, "handleHomePage", layoutContent)
}

func apiScoreboard(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		jsonEncoder := json.NewEncoder(writer)
		writer.Header().Add("Content-Type", "application/json")
		scoreboardData, _ := api.GetScoreboardData(db)
		jsonEncoder.Encode(string(scoreboardData))

	default:
		writer.WriteHeader(http.StatusMethodNotAllowed)
		writer.Write([]byte("Method not allowed."))
	}
}

/* --- Page handler outline ---
1. Generate whatever data is needed for input parameters to the HTML templates.
2. Create parameters mapping for page-specific template.
3. Fill the page-specific template.
4. Create parameters mapping for layout template, including your page-specific templated HTML.
5. Serve the full templated layout page.
*/

func handleRequests() {
	// TODO: Add request logging
	http.HandleFunc("/", handleHomePage)
	http.HandleFunc("/api/scoreboard", apiScoreboard)
	http.HandleFunc("/login", handleLoginPage)
	http.Handle("/dashboard", isAuthorized(handleDashboardPage))
}

func main() {
	var argTest bool
	var argPort int
	flag.BoolVar(&argTest, "test", false, "Listen on localhost instead of the default interface's IP address")
	flag.IntVar(&argPort, "port", 443, "Port to listen on")
	flag.Parse()

	utils.Log(utils.Debug, "----------Initializing----------")

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

	certPath := utils.CurrentDirectory + "/pwnts_cert.pem"
	privateKeyPath := utils.CurrentDirectory + "/pwnts_key.pem"

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
	utils.Log(utils.Debug, "----------Activity Logs---------")

	// https://pkg.go.dev/net/http#FileServer
	// Allow the hosting of static files like our images and stylesheets
	staticFileServer := http.FileServer(http.Dir(utils.CurrentDirectory + "/site/static"))
	// TODO: Figure out why the FileServer isn't setting the correct Content-Type header MIME type on JavaScript files.
	//		 Should be "text/javascript" but is "text/plain"
	http.Handle("/static/", http.StripPrefix("/static/", staticFileServer))

	// Register page handlers
	handleRequests()

	err := http.ListenAndServeTLS(listenAddress, certPath, privateKeyPath, nil)
	utils.CheckErrorExit(utils.Error, err, utils.ERR_GENERIC, "Couldn't start HTTPS listener at", listenAddress)
}
