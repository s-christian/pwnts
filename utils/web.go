package utils

import (
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"time"

	"github.com/google/uuid"
)

const (
	maxCallbackTime time.Duration = 15 * time.Minute
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

func RegisterAgent(agentUUID string, teamID int) { //, serverPrivateKey string, agentPublicKey string, createdDate int, rootDate int) {
	Log(Info, "Registering Agent", agentUUID)

	// Check if the provided string is a valid UUID format
	_, err := uuid.Parse(agentUUID)
	CheckErrorExit(Error, err, ERR_UUID, "Provided UUID string is not a valid UUID")

	db := GetDatabaseHandle()
	// don't need to ValidateDatabaseExit() here since that's already done for us
	// in validateTeamID(), always called before this function.
	defer Close(db)

	addAgentSQL := `
		INSERT INTO Agents(agent_uuid, team_id, server_private_key, agent_public_key, created_date_unix, root_date_unix)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	addAgentStatement, err := db.Prepare(addAgentSQL)
	if CheckError(Error, err, "\tCould not create AddTarget statement") {
		return
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
		return
	}

	// Count total Agents
	agentsCount := db.QueryRow("SELECT COUNT(*) FROM Agents")
	var numAgents int
	agentsCount.Scan(&numAgents)

	Log(Done, "\tRegistered Agent", agentUUID)
	Log(Done, "\tThere are now", fmt.Sprint(numAgents), "registered Agents")
}
