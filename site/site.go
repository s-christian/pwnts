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
	// htmlFilepath := utils.CurrentDirectory + "site/pages/" + htmlFilename
	// pageHTML, err := os.ReadFile(htmlFilepath)
	// if utils.CheckWebError(writer, request, err, "Could not read '/"+htmlFilename+"' page", functionName) {
	// 	return
	// }

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

	// Return templated HTML
	var contentHTML bytes.Buffer
	err = contentTemplate.Execute(&contentHTML, pageContent)
	if utils.CheckWebError(writer, request, err, functionName+": Couldn't execute template", functionName) {
		return template.HTML(`<p style="color: red; font-weight: bold;">Error fetching page content</p>`)
	}

	if contentHTML.String() == "" {
		utils.Log(utils.Error, functionName+": Template returned no data")
		return template.HTML(`<p style="color: red; font-weight: bold;">Error fetching page content</p>`)
	}

	return template.HTML(contentHTML.String())
}

func handleDashboardPage(writer http.ResponseWriter, request *http.Request) {
	// dashboardPageHTMLFile := utils.CurrentDirectory + "site/pages/dashboard.html"
	// dashboardPageHTML, err := os.ReadFile(dashboardPageHTMLFile)
	// if utils.CheckWebError(writer, request, err, "Could not read '/dashboard.html' page", "handleDashboardPage") {
	// 	return
	// }

	dashboardContent := map[string]template.HTML{"testString": "Hello, Dashboard!"}
	dashboardHTML := returnTemplateHTML(writer, request, "dashboard.html", "handleDashboardPage", dashboardContent)

	layoutContent := map[string]template.HTML{"title": "Red Team Dashboard", "pageContent": dashboardHTML}
	serveLayoutTemplate(writer, request, "handleDashboardPage", layoutContent)

	// generalTemplate, err := template.ParseFiles("templates/general.html")
	// if utils.CheckWebError(writer, request, err, "handleDashboardPage: Can't parse template", "handleDashboardPage") {
	// 	return
	// }
	// err = generalTemplate.Execute(writer, dashboardContent)
	// if utils.CheckWebError(writer, request, err, "handleDashboardPage: Couldn't execute template", "handleDashboardPage") {
	// 	return
	// }
}

func handleLoginPage(writer http.ResponseWriter, request *http.Request) {
	loginContent := map[string]template.HTML{"testString": "Hello, Login!"}
	loginHTML := returnTemplateHTML(writer, request, "login.html", "handleLoginPage", loginContent)

	layoutContent := map[string]template.HTML{"title": "Login", "pageContent": loginHTML}
	serveLayoutTemplate(writer, request, "handleLoginPage", layoutContent)

	// loginPageHTMLFile := utils.CurrentDirectory + "/site/pages/login.html"
	// loginPageHTML, err := os.ReadFile(loginPageHTMLFile)
	// if utils.CheckError(utils.Error, err, "Could not read '/login.html' page") {
	// 	_, err = fmt.Fprint(writer, "Could not serve '"+request.Method+" "+request.URL.RequestURI()+"'")
	// 	utils.CheckError(utils.Error, err, "handleLoginPage: Couldn't write to http.ResponseWriter")
	// } else {
	// 	_, err = fmt.Fprint(writer, string(loginPageHTML))
	// 	utils.CheckError(utils.Error, err, "handleLoginPage: Couldn't write to http.ResponseWriter")
	// }
}

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

func handleHomePage(writer http.ResponseWriter, request *http.Request) {
	// loginContent := pageInfo{Title: "Login", Content: template.HTML("<p>Login</p>\n<p>Lorem ipsum...</p>")}
	// serveGeneralTemplate(writer, request, "login.html", "handleLoginPage", &loginContent)
	// jwt, err := generateJWT()
	// if utils.CheckError(utils.Error, err, "Could not sign JWT") {
	// 	_, err = fmt.Fprint(writer, err.Error())
	// 	utils.CheckError(utils.Error, err, "handleHomePage: Couldn't write to http.ResponseWriter")
	// } else {
	// 	homePageHTMLFile := utils.CurrentDirectory + "/site/pages/index.html"
	// 	homePageHTML, err := os.ReadFile(homePageHTMLFile)
	// 	if utils.CheckError(utils.Error, err, "Could not read '/index.html' page") {
	// 		_, err = fmt.Fprint(writer, "Could not serve '"+request.Method+" "+request.URL.RequestURI()+"'")
	// 		utils.CheckError(utils.Error, err, "handleHomePage: Couldn't write to http.ResponseWriter")
	// 	} else {
	// 		_, err = fmt.Fprint(writer, string(homePageHTML)+"\n"+jwt)
	// 		utils.CheckError(utils.Error, err, "handleHomePage: Couldn't write to http.ResponseWriter")
	// 	}
	// }

	// Generate the data we want to pass to the page-specific template
	jwt, err := generateJWT()
	if utils.CheckWebError(writer, request, err, "Could not sign JWT", "handleHomePage") {
		return
	}

	// The parameters to full the page-specific template
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
