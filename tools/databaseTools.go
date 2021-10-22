package main

/*
	Flags:
		--init-db:			Initialize the database by creating the Teams and Agents Sqlite3 tables.
		--register-targets:	Add targets by their IP address and point value. Targets are defined
							in the file "targets.txt" in the CSV format "ip,point_value".
		--register-agent:	Register an Agent UUID.
*/

import (
	"bufio"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/s-christian/pwnts/utils"
)

// Flag: --register-agent
func registerAgent(agentUUID string, teamID int) { //, serverPrivateKey string, agentPublicKey string, createdDate int, rootDate int) {
	utils.Log(utils.Info, "Registering Agent", agentUUID)

	// Check if the provided string is a valid UUID format
	_, err := uuid.Parse(agentUUID)
	utils.CheckErrorExit(utils.Error, err, utils.ERR_UUID, "Provided UUID string is not a valid UUID")

	db := utils.GetDatabaseHandle()
	// don't need to ValidateDatabaseExit() here since that's already done for us
	// in validateTeamID(), always called before this function.
	defer utils.CloseDatabase(db)

	addAgentSQL := `
		INSERT INTO Agents(agent_uuid, team_id, server_private_key, agent_public_key, created_date_unix, root_date_unix)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	addAgentStatement, err := db.Prepare(addAgentSQL)
	if utils.CheckError(utils.Error, err, "\tCould not create AddTarget statement") {
		return
	}
	defer addAgentStatement.Close()

	// TODO: Randomly generate this crypto keypair
	serverPrivateKey := "555"
	agentPublicKey := "555"

	createdDate := int(time.Now().Unix())
	rootDate := 0 // no agents have root status until proven by their first callback

	_, err = addAgentStatement.Exec(agentUUID, teamID, serverPrivateKey, agentPublicKey, createdDate, rootDate)
	if utils.CheckError(utils.Warning, err, "\tCould not register Agent") {
		return
	}

	// Count total Agents
	agentsCount := db.QueryRow("SELECT COUNT(*) FROM Agents")
	var numAgents int
	agentsCount.Scan(&numAgents)

	utils.Log(utils.Done, "\tRegistered Agent", agentUUID)
	utils.Log(utils.Done, "\tThere are now", fmt.Sprint(numAgents), "registered Agents")
}

// Helper function called before registerAgent()
func validateTeamID(teamID int) {
	utils.Log(utils.Info, "Validating Team ID")

	db := utils.GetDatabaseHandle()
	utils.ValidateDatabaseExit(db)
	defer utils.CloseDatabase(db)

	validateTeamIDSQL := `
		SELECT team_id, name, created_date_unix FROM Teams
		WHERE team_id = ?
	`
	validateTeamIDStatement, err := db.Prepare(validateTeamIDSQL)
	utils.CheckErrorExit(utils.Error, err, utils.ERR_STATEMENT, "[!] Could not create ValidateTeamID statement")

	var dbTeamID int
	var dbTeamName string
	var dbTeamCreatedDate int64 // stored as UNIX time, seconds since epoch, not a time.Duration
	err = validateTeamIDStatement.QueryRow(teamID).Scan(&dbTeamID, &dbTeamName, &dbTeamCreatedDate)
	if err == sql.ErrNoRows { // invalid Team ID (doesn't exist)
		color.New(color.FgRed, color.Bold).Println("[!] Team ID", fmt.Sprint(teamID), "does not exist")
		os.Exit(utils.ERR_INPUT)
	}
	if err != nil { // genuine DB error
		color.New(color.FgRed, color.Bold).Println("[!] Could not execute ValidateTeamID statement")
		os.Exit(utils.ERR_QUERY)
	}

	utils.Log(utils.Done, "[+] Team '"+dbTeamName+"' (ID "+fmt.Sprint(teamID)+", created "+time.Unix(dbTeamCreatedDate, 0).Format(time.RFC3339)+") is valid")
}

// Flag: --register-targets
func registerTargetsFromFile(filename string) {
	utils.Log(utils.Info, "Registering targets:")

	db := utils.GetDatabaseHandle()
	utils.ValidateDatabaseExit(db)
	defer utils.CloseDatabase(db)

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

// Flag: --init-db
func initializeDatabase() {
	utils.Log(utils.Info, "Initializing database")
	utils.Log(utils.Debug, "If recreating the entire database, please manually remove the database file")

	// Create database file if it doesn't exist
	if _, err := os.Stat(utils.DatabaseFilepath); os.IsNotExist(err) {
		dbFile, err := os.Create(utils.DatabaseFilepath)
		utils.CheckErrorExit(utils.Error, err, utils.ERR_GENERIC, "Could not create database file")

		utils.Log(utils.Done, "Created database file \""+utils.DatabaseFilename+"\"")
		dbFile.Close()
	}

	// Open database (file exists)
	db := utils.GetDatabaseHandle()
	if utils.ValidateDatabase(db) { // no need to initialize database if it's already valid
		utils.Log(utils.Done, "No need to initialize database")
		return
	}
	defer utils.CloseDatabase(db)

	const createTablesFile string = "/server/create_tables.txt" // default
	createTablesCommands, err := os.ReadFile(utils.CurrentDirectory + createTablesFile)
	utils.CheckErrorExit(utils.Error, err, utils.ERR_FILE_READ, "Could not read file \"create_tables.txt\"")

	statement, err := db.Prepare(string(createTablesCommands))
	utils.CheckErrorExit(utils.Error, err, utils.ERR_STATEMENT, "Could not create CreateTablesCommands statement")
	defer statement.Close()

	_, err = statement.Exec()
	if err != nil {
		utils.LogError(utils.Error, err, "Could not create tables")
		os.Exit(utils.ERR_GENERIC)
	}

	utils.Log(utils.Done, "Database initialized")
}

func main() {

	// Flags can be used with '--name' or '-name', doesn't matter.
	var argInitDB bool
	var argRegisterTargetsFromFile string
	var argRegisterAgentUUID string
	var argTeamID int

	flag.BoolVar(&argInitDB, "init-db", false, "Initialize the database by creating the Teams and Agents Sqlite3 tables")
	flag.StringVar(&argRegisterTargetsFromFile, "register-targets", "", "Add targets by their IP address and point value. By default, targets are defined in the file \"/server/targets.txt\" in the CSV format \"ip,point_value\".")
	flag.StringVar(&argRegisterAgentUUID, "register-agent", "", "Register an Agent UUID.")
	flag.IntVar(&argTeamID, "team-id", -1, "The Team ID the Agent should belong to. (Required if using the `--register-agent` flag)")

	flag.Parse()

	// Flag: --init-db
	if argInitDB {
		initializeDatabase()
		os.Exit(0)
	}

	// Flag: --register-targets
	if argRegisterTargetsFromFile != "" {
		registerTargetsFromFile(argRegisterTargetsFromFile)
		os.Exit(0)
	}

	// Flag: --register-agent
	if argRegisterAgentUUID != "" {
		if argTeamID == -1 {
			color.New(color.FgRed, color.Bold).Println("[!] Please specify a `--team-id <integer>`")
			os.Exit(utils.ERR_USAGE)
		}

		validateTeamID(argTeamID)
		registerAgent(argRegisterAgentUUID, argTeamID)
	}

	// If this is reached, no command-line flag (action) has been specified.
	color.New(color.FgYellow, color.Bold).Println("[*] Please specify an action.")
	color.New(color.FgMagenta).Println("------------------------------------------------------------")
	flag.Usage()
	color.New(color.FgMagenta).Println("------------------------------------------------------------")
}