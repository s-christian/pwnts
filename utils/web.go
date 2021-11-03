// Utility functions used be `site/site.go` and `tools/databaseTools.go`.
// Functions in `web.go` should generally not interrupt the flow of the application by exiting on error. Instead, they should return their error status to be handled by the calling function.
package utils

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/google/uuid"
)

const (
	maxCallbackTime   time.Duration = 15 * time.Minute
	maxTeamNameLength int           = 64
)

// Handle any errors encountered when trying to serve a web page
func CheckWebError(writer http.ResponseWriter, request *http.Request, err error, errorMessage string, functionName string) bool {
	if CheckError(Error, err, errorMessage) {
		_, err := fmt.Fprint(writer, "Could not serve '"+request.Method+" "+request.URL.RequestURI()+"'")
		CheckError(Error, err, functionName+": Couldn't write to http.ResponseWriter")
		return true
	}
	return false
}

func CalculateCallbackPoints(timeDifference time.Duration, targetValue int) int {
	// Only care about minutes, in cases where a callback might be 5 milliseconds off or something negligible we don't care about.
	// We don't want to round on minimum time, but rounding on maximum time is fine.
	// 14.50 => 15, 15.49 => 15
	if timeDifference.Round(time.Minute) > maxCallbackTime {
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

func CheckPasswordHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil // correct password if err == nil
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
	if len(teamName) > maxTeamNameLength {
		return errors.New("error registering team: team name can't be longer than " + fmt.Sprint(maxTeamNameLength) + " characters")
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
