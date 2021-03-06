// Utility functions used be `site/site.go` and `tools/databaseTools.go`.
// Functions in `web.go` should generally not interrupt the flow of the application by exiting on error. Instead, they should return their error status to be handled by the calling function.
package utils

import (
	"database/sql"
	"errors"
	"fmt"

	//"html/template"
	"encoding/json"
	"math"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

const (
	MaxCallbackTime   time.Duration = 15 * time.Minute
	MaxTeamNameLength int           = 64
)

var (
	JWTSigningKey []byte = []byte("supersecretsecret")
)

// https://pkg.go.dev/encoding/json#Marshal
type (
	ReturnMessage struct {
		Message string `json:"message"`
		Error   bool   `json:"error"`
	}
)

/*
	Handle any errors encountered when trying to serve a web page by setting
	the the response status to 500: Internal Server Error.
*/
func CheckWebError(writer http.ResponseWriter, request *http.Request, err error, errorMessage string) bool {
	if CheckError(Error, err, errorMessage) {
		writer.WriteHeader(http.StatusInternalServerError)
		//writer.Write([]byte(string(template.HTML(`<p style="color: red; font-weight: bold;">`)) + "'" + request.Method + " " + request.URL.RequestURI() + "'" + string(template.HTML(`</p>`))))
		return true
	}
	return false
}

/*
	Log the IP address of the request with the specified error level and
	message.
*/
func LogIP(messageType logType, request *http.Request, messages ...string) {
	Log(messageType, append([]string{GetUserIP(request) + ":"}, messages...)...)
}

/*
	Extract the first value from the specified form field. Automatically
	runs ValidateFormData to check for errors.
*/
func GetFormDataSingle(writer http.ResponseWriter, request *http.Request, dataName string) (dataSingle string) {
	// Necessary to populate the request.Form and request.PostForm attributes
	err := request.ParseMultipartForm(1024)
	if err != nil {
		ReturnStatusServerError(writer, request, "Could not parse form data")
		LogIP(Error, request, "Could not parse POSTed form data. Malicious?")
		return
	}

	formData := request.PostForm[dataName]

	// Check that the
	if ValidateFormData(writer, request, formData, 1, 1) {
		dataSingle = formData[0]
	}

	return
}

/*
	Ensure that the form field contains the expected number of objects.
*/
func ValidateFormData(writer http.ResponseWriter, request *http.Request, formData []string, minObjects int, maxObjects int) bool {
	if len(formData) < minObjects || len(formData) > maxObjects {
		ReturnStatusUserError(writer, request, "Must provide value for 'callbackMins'")
		LogIP(Error, request, "Invalid "+request.Method+" request to '"+request.RequestURI+"'. Malicious?")
		return false
	} else {
		return true
	}
}

func GetUserIP(request *http.Request) string {
	IPAddress := request.Header.Get("X-Real-Ip")
	if IPAddress != "" {
		IPAddress = strings.Split(IPAddress, ", ")[0]
	} else { // header was empty
		IPAddress = request.Header.Get("X-Forwarded-For")
		if IPAddress == "" { // header was empty
			IPAddress = request.RemoteAddr // extract IP from request (usually least accurate)
		}
	}
	return IPAddress
}

/*
	Parses the JSON Web Token "auth" cookie and returns its claims as
	jwt.MapClaims.
*/
func GetAuthClaims(writer http.ResponseWriter, request *http.Request) (authClaims jwt.MapClaims, err error) {
	// Get auth cookie
	authCookie, err := request.Cookie("auth")
	// If cookie doesn't exist
	if err != nil {
		http.Redirect(writer, request, "/login", http.StatusFound)
		return
	}

	authClaims, err = GetJWTClaims(authCookie, writer, request)
	return
}

/*
	Parses the provided JSON Web Token cookie and returns its claims as
	jwt.MapClaims.
*/
func GetJWTClaims(jwtCookie *http.Cookie, writer http.ResponseWriter, request *http.Request) (tokenClaims jwt.MapClaims, err error) {
	// Parse token
	token, err := jwt.Parse(
		jwtCookie.Value,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("incorrect signing method")
			}

			// Return the signing key for token validation
			return JWTSigningKey, nil
		},
	)

	// Token is not a proper JWT, is expired, or does not use the correct
	// signing method
	if err != nil {
		return
	}

	// I believe the above jwt.Parse() already does all of the token validation
	// for us, but the below checks are "just in case".

	// Check if the JWT is valid
	if !token.Valid {
		err = errors.New("token invalid")
		return
	}

	// Type the claims as jwt.MapClaims
	if mapClaims, ok := token.Claims.(jwt.MapClaims); !ok {
		err = errors.New("token claims invalid")
		return
	} else {
		// Make sure the token isn't expired (current time > exp).
		// Automatically uses the RFC standard "exp", "iat", and "nbf" claims,
		// if they exist, with values interpretted as UNIX seconds.
		err = mapClaims.Valid()
		if err != nil {
			return
		}

		tokenClaims = token.Claims.(jwt.MapClaims)
	}

	if len(tokenClaims) == 0 {
		err = errors.New("token claims don't exist")
		return
	}

	return
}

func ClearAuthCookieAndRedirect(writer http.ResponseWriter, request *http.Request, err error) {
	LogIP(Warning, request, "Invalid token -", err.Error())

	// Delete the expired auth cookie
	newAuthCookie := http.Cookie{Name: "auth", Value: "", MaxAge: -1, Secure: true, HttpOnly: true}
	http.SetCookie(writer, &newAuthCookie)

	// Redirect to the `/login` page
	http.Redirect(writer, request, "/login", http.StatusFound)
}

func GenerateJWT(db *sql.DB, username string, teamID int) (tokenStirng string, err error) {
	/*
		--- Token Payload (Claims) ---
		"user": <team_name>,
		"teamId": <team_id>,
		"teamName": <team_name>,
		"exp": <timestamp_unix_seconds>

		JWT is stored as a cookie with the name "auth"
	*/

	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	teamName, err := GetTeamName(db, teamID)
	if err != nil {
		return
	}

	claims["user"] = username
	claims["teamId"] = teamID
	claims["teamName"] = teamName
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix() // token expires after 30 minutes

	tokenString, err := token.SignedString(JWTSigningKey)

	return tokenString, err
}

func ReturnStatusJSON(writer http.ResponseWriter, request *http.Request, message string, isError bool) {
	// Send JSON response
	err := json.NewEncoder(writer).Encode(&ReturnMessage{Message: message, Error: isError})
	// Check for encoding error
	CheckWebError(writer, request, err, "Could not encode login response to JSON")
}
func ReturnStatusSuccess(writer http.ResponseWriter, request *http.Request, message string) {
	ReturnStatusJSON(writer, request, message, false)
}
func ReturnStatusUserError(writer http.ResponseWriter, request *http.Request, message string) {
	writer.WriteHeader(http.StatusUnauthorized)
	ReturnStatusJSON(writer, request, message, true)
}
func ReturnStatusServerError(writer http.ResponseWriter, request *http.Request, message string) {
	writer.WriteHeader(http.StatusInternalServerError)
	ReturnStatusJSON(writer, request, message, true)
}

func PromptFileDownload(writer http.ResponseWriter, request *http.Request, filePath string, fileName string) {
	writer.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(fileName))
	writer.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(writer, request, filePath)
}

func CalculateCallbackPoints(timeDifference time.Duration, targetValue int) int {
	// Only care about minutes, in cases where a callback might be 5 milliseconds off or something negligible we don't care about.
	// We don't want to round on minimum time, but rounding on maximum time is fine.
	// 14.50 => 15, 15.49 => 15
	if timeDifference.Round(time.Minute) > MaxCallbackTime {
		return 1 // only 1 point
	}

	// Exponential decay in point value
	// 1.2^(-0.9(x-1))
	// 1 minute = 100 points, 5 minutes = 52 points, 10 minutes = 23 points, 15 minutes = 10 points
	// Since UNIX time is used, accuracy is down to the second
	// Score is calculated as minutes between callbacks
	const baseValue float64 = 1.2
	const decayValue float64 = -0.9
	return int(math.Round(float64(targetValue) * math.Pow(baseValue, (decayValue*(float64(timeDifference/time.Minute)-1)))))
}

func GetTeamName(db *sql.DB, teamID int) (teamName string, err error) {
	getTeamNameSQL := `
		SELECT name
		FROM Teams
		WHERE team_id = ?
	`
	getTeamNameStatement, err := db.Prepare(getTeamNameSQL)
	if err != nil {
		return
	}

	err = getTeamNameStatement.QueryRow(teamID).Scan(&teamName)
	Close(getTeamNameStatement)

	return
}

func GetTeamNames(db *sql.DB) ([]string, error) {
	var teamNames []string
	var err error

	getTeamNamesSQL := `
		SELECT name
		FROM Teams
	`
	getTeamNamesStatement, err := db.Prepare(getTeamNamesSQL)
	if err != nil {
		return teamNames, err
	}

	teamNamesRows, err := getTeamNamesStatement.Query()
	if err != nil {
		return teamNames, err
	}
	Close(getTeamNamesStatement)

	for teamNamesRows.Next() {
		err = teamNamesRows.Err()
		if err != nil {
			return teamNames, err
		}

		var dbTeamName string
		err = teamNamesRows.Scan(&dbTeamName)
		if err != nil {
			return teamNames, err
		}

		teamNames = append(teamNames, dbTeamName)
	}
	Close(teamNamesRows)

	return teamNames, err
}

/*
	Returns the teamId, name, password_hash, and created_date_unix for the
	specified username, as well as an err if needed.

	If user does not exist, err = sql.ErrNoRows
	If backend server error, err = some error
	Else, err = nil
*/
func GetUserInfo(db *sql.DB, username string) (teamId int, name string, passwordHash string, createdDateUnix int, err error) {
	getUserInfoSQL := `
		SELECT *
		FROM Teams
		WHERE name = ?
	`
	getUserInfoStatement, err := db.Prepare(getUserInfoSQL)
	if CheckError(Error, err, "Could not prepare GetUserInfo statement") {
		return
	}

	userInfoRow := getUserInfoStatement.QueryRow(username)
	Close(getUserInfoStatement)

	err = userInfoRow.Scan(&teamId, &name, &passwordHash, &createdDateUnix)
	if err == sql.ErrNoRows {
		Log(Warning, "Attempted login for non-existent user '"+username+"'")
	} else if err != nil {
		LogError(Error, err, "Could not query using GetUserInfo statement")
	}

	return
}

func ValidatePasswordHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil // err == nil means incorrect password
}

func HashPassword(password string) (string, error) {
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	CheckError(Error, err, "Could not hash provided password")

	return string(hashBytes), err
}

/*
	Register a new Team by its name and password hash.

	Returns `EXIT_SUCCESS` upon successful Team creation.

	Otherwise, upon error, returns one of `ERR_INPUT` (team name too long), `ERR_STATEMENT`, or `ERR_QUERY`.
*/
func RegisterTeam(db *sql.DB, teamName string, teamPasswordHash string) error {
	Log(List, "Registering new Team")

	var err error

	// Check that team name <= maxTeamNameLength
	if len(teamName) > MaxTeamNameLength {
		return errors.New("error registering team: team name can't be longer than " + fmt.Sprint(MaxTeamNameLength) + " characters")
	}

	// Check that new team name doesn't match pre-existing team name, stripping special characters for the comparison
	reg, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		return err
	}

	dbTeamNames, err := GetTeamNames(db)
	if err != nil {
		return err
	}
	for _, dbTeamName := range dbTeamNames {
		if strings.EqualFold(reg.ReplaceAllLiteralString(teamName, ""), reg.ReplaceAllLiteralString(dbTeamName, "")) {
			return errors.New("error registering team: new team name is too similar to a pre-existing team name")
		}
	}

	// Prepare statement
	registerTeamSQL := `
		INSERT INTO Teams(name, password_hash, created_date_unix)
		VALUES (?, ?, ?)
	`
	registerTeamStatement, err := db.Prepare(registerTeamSQL)
	if err != nil {
		return err
	}
	defer Close(registerTeamStatement)

	// Register Team
	createdDate := int(time.Now().Unix())
	registerTeamResult, err := registerTeamStatement.Exec(teamName, teamPasswordHash, createdDate)
	if err != nil {
		return err
	}

	// Print success (with possible warning of not knowing Team ID, if not returned by the database driver)
	newTeamID, warn := registerTeamResult.LastInsertId()
	if CheckError(Warning, warn, "Could not retrieve the ID for the newly-registered Team '"+teamName+"'") {
		Log(Done, fmt.Sprintf("Team '%s' (ID: UNKNOWN) has been registered", teamName))
	} else {
		Log(Done, fmt.Sprintf("Team '%s' (ID: %d) has been registered", teamName, newTeamID))
	}

	return err
}

/*
	Validate user login, checking that the user exists and that their hashed password matches the hash in the database.

	A bool is returned as well as an error (potentially nil) to distinguish between failed authentication and backend error.
*/
// func ValidateLogin(db *sql.DB, username string, password string) (bool, error) {
// 	passwordHash, err := GetUserPasswordHash(db, username)
// 	if err != nil {
// 		return false, err
// 	}
// 	return CheckPasswordHash(password, passwordHash), nil
// }

func RegisterAgent(db *sql.DB, agentUUID string, teamID int) bool { //, serverPrivateKey string, agentPublicKey string, createdDate int, rootDate int) {
	Log(Info, "Registering Agent", agentUUID)

	// Check if the provided string is a valid UUID format
	_, err := uuid.Parse(agentUUID)
	CheckErrorExit(Error, err, ERR_UUID, "Provided UUID string is not a valid UUID")

	addAgentSQL := `
		INSERT INTO Agents(agent_uuid, team_id, server_private_key, agent_public_key, created_date_unix, root_date_unix)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	addAgentStatement, err := db.Prepare(addAgentSQL)
	if CheckError(Error, err, "\tCould not create AddAgent statement") {
		return false
	}
	defer Close(addAgentStatement)

	// TODO: Randomly generate this crypto keypair
	// Temporary random number generators to satisfy the unique constraint
	// TODO: Actually use the crypto keypair. The field currently only exists
	// for future use and is not yet used. Should be used for encrypting
	// communications.
	randSource := rand.NewSource(time.Now().UnixNano())
	seededRand := rand.New(randSource)
	serverPrivateKey := seededRand.Intn(1000)

	randSource = rand.NewSource(time.Now().UnixNano())
	seededRand = rand.New(randSource)
	agentPublicKey := seededRand.Intn(1000)

	createdDate := int(time.Now().Unix())
	rootDate := 0 // no agents have root status until proven by their first callback

	_, err = addAgentStatement.Exec(agentUUID, teamID, serverPrivateKey, agentPublicKey, createdDate, rootDate)
	if CheckError(Warning, err, "\tCould not register Agent") {
		return false
	}

	// Count total Agents
	agentsCount := db.QueryRow("SELECT COUNT(*) FROM Agents")
	var numAgents int
	err = agentsCount.Scan(&numAgents)
	if CheckError(Error, err, "\tCould not scan GetAgentCount") {
		return false
	}

	Log(Done, "\tRegistered Agent", agentUUID)
	Log(Done, "\tThere are now", fmt.Sprint(numAgents), "registered Agents")
	return true
}
