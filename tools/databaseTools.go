package main

/*
	Flags:
		--init-db:			Initialize the database by creating the Teams and Agents Sqlite3 tables.
		--register-targets:	Add targets by their IP address and point value. Targets are defined
							in the file "targets.txt" in the CSV format "ip,point_value".
		--register-team:	Create a team with --team-name and --team-password.
			--team-name:		The name of the team.
			--team-password:	The plaintext password for the team (to be hashed with bcrypt).
		--register-agent:	Register an Agent UUID.
*/

import (
	"bufio"
	"database/sql"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/s-christian/pwnts/utils"
)

// Helper function called before registerAgent()
func validateTeamID(db *sql.DB, teamID int) {
	utils.Log(utils.Info, "Validating Team ID")

	validateTeamIDSQL := `
		SELECT team_id, name, created_date_unix
		FROM Teams
		WHERE team_id = ?
	`
	validateTeamIDStatement, err := db.Prepare(validateTeamIDSQL)
	utils.CheckErrorExit(utils.Error, err, utils.ERR_STATEMENT, "[!] Could not create ValidateTeamID statement")
	defer utils.Close(validateTeamIDStatement)

	var dbTeamID int
	var dbTeamName string
	var dbTeamCreatedDate int // stored as UNIX time, seconds since epoch, not a time.Duration
	err = validateTeamIDStatement.QueryRow(teamID).Scan(&dbTeamID, &dbTeamName, &dbTeamCreatedDate)
	if err == sql.ErrNoRows { // invalid Team ID (doesn't exist)
		utils.CheckErrorExit(utils.Error, err, utils.ERR_INPUT, "Team ID", fmt.Sprint(teamID), "does not exist")
	}
	utils.CheckErrorExit(utils.Error, err, utils.ERR_QUERY, "Could not execute ValidateTeamID statement") // genuine db error

	utils.Log(utils.Done, "Team '"+dbTeamName+"' (ID "+fmt.Sprint(teamID)+", created "+time.Unix(int64(dbTeamCreatedDate), 0).Format(time.RFC3339)+") is valid")
}

// Flag: --register-targets
func registerTargetsFromFile(db *sql.DB, filename string) {
	utils.Log(utils.Info, "Registering targets:")

	fullFilePath := utils.CurrentDirectory + filename
	targetsFile, err := os.Open(fullFilePath)
	utils.CheckErrorExit(utils.Error, err, utils.ERR_GENERIC, "Cannot open file '"+fullFilePath+"'")
	defer utils.Close(targetsFile)

	addTargetSQL := `
		INSERT INTO TargetsInScope(target_ipv4_address, value)
		VALUES (?, ?)
	`
	addTargetStatement, err := db.Prepare(addTargetSQL)
	utils.CheckErrorExit(utils.Error, err, utils.ERR_GENERIC, "Could not create AddTarget statement")
	defer utils.Close(addTargetStatement)

	scanner := bufio.NewScanner(targetsFile)
	addedCounter, lineCounter := 0, 0
	for scanner.Scan() {
		lineCounter++
		lineCSV := strings.Split(scanner.Text(), ",")

		if len(lineCSV) != 2 {
			utils.Log(utils.Warning, "\tSkipping target "+fmt.Sprint(lineCounter)+": target entries must be on separate lines in the form of 'ip,value'")
			continue
		}

		var targetIP net.IP = net.ParseIP(lineCSV[0])
		if targetIP == nil {
			utils.Log(utils.Warning, "\tSkipping target "+fmt.Sprint(lineCounter)+": '"+lineCSV[0]+"' is not a valid IP address")
			continue
		}

		var targetValue int
		_, err = fmt.Sscan(lineCSV[1], &targetValue)

		if utils.CheckError(utils.Warning, err, "\tSkipping target "+fmt.Sprint(lineCounter)+": '"+lineCSV[1]+"' is not an integer") {
			continue
		}

		utils.Log(utils.List, "Target IP: "+targetIP.String()+",\tValue: "+fmt.Sprint(targetValue))

		_, err := addTargetStatement.Exec(targetIP.String(), targetValue)

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
	defer utils.Close(db)
	if utils.ValidateDatabase(db) { // no need to initialize database if it's already valid
		utils.Log(utils.Done, "No need to initialize database")
		return
	}

	const createTablesFile string = "/tools/create_tables.sql" // default
	createTablesFileContents, err := os.ReadFile(utils.CurrentDirectory + createTablesFile)
	utils.CheckErrorExit(utils.Error, err, utils.ERR_FILE_READ, "Could not read file \""+createTablesFile+"\"")

	createTablesCommands := strings.Split(string(createTablesFileContents), ";")

	for i, command := range createTablesCommands {
		statement, err := db.Prepare(command)
		defer utils.Close(statement)
		if utils.CheckError(utils.Error, err, "Could not create statement for table #"+fmt.Sprint(i+1)) {
			continue
		}

		_, err = statement.Exec()
		if err != nil {
			utils.LogError(utils.Error, err, "Could not create tables")
			os.Exit(utils.ERR_GENERIC)
		}
	}

	utils.Log(utils.Done, "Database initialized")
}

func main() {

	// Flags can be used with '--name' or '-name', doesn't matter.
	var argInitDB bool
	var argRegisterTargetsFromFile string
	var argRegisterTeam bool
	var argRegisterTeamName string
	var argRegisterTeamPassword string
	var argRegisterAgentUUID string
	var argTeamID int

	flag.BoolVar(&argInitDB, "init-db", false, "Initialize the database by creating the Teams and Agents Sqlite3 tables")
	flag.StringVar(&argRegisterTargetsFromFile, "register-targets", "", "Add targets by their IP address and point value. Targets are defined in the file \"targets.txt\" in the CSV format \"ip,point_value\".")
	flag.BoolVar(&argRegisterTeam, "register-team", false, "Create a team with --team-name and --team-password.")
	flag.StringVar(&argRegisterTeamName, "team-name", "", "The name of the team.")
	flag.StringVar(&argRegisterTeamPassword, "team-password", "", "The plaintext password for the team (to be hashed with bcrypt).")
	flag.StringVar(&argRegisterAgentUUID, "register-agent", "", "Register an Agent UUID.")
	flag.IntVar(&argTeamID, "team-id", -1, "The Team ID the Agent should belong to. (Required if using the `--register-agent` flag)")

	flag.Parse()

	// Flag: --init-db
	if argInitDB {
		initializeDatabase()
		os.Exit(utils.EXIT_SUCCESS)
	}

	db := utils.GetDatabaseHandle()
	utils.ValidateDatabaseExit(db)
	defer utils.Close(db)

	// Flag: --register-targets
	if argRegisterTargetsFromFile != "" {
		registerTargetsFromFile(db, argRegisterTargetsFromFile)
		os.Exit(utils.EXIT_SUCCESS)
	}

	// Flag: --register-team
	if argRegisterTeam {
		if argRegisterTeamName == "" || argRegisterTeamPassword == "" {
			utils.LogPlainExit(utils.Error, utils.ERR_USAGE, "A `--team-name` and `--team-password` must be provided")
		}

		passwordHash, err := utils.HashPassword(argRegisterTeamPassword)
		if err != nil {
			os.Exit(utils.ERR_INPUT)
		}

		err = utils.RegisterTeam(db, argRegisterTeamName, passwordHash)
		if utils.CheckError(utils.Error, err, "Could not register Team") {
			os.Exit(utils.ERR_QUERY)
		}
		os.Exit(utils.EXIT_SUCCESS)
	}

	// Flag: --register-agent
	if argRegisterAgentUUID != "" {
		if argTeamID == -1 {
			utils.LogPlainExit(utils.Error, utils.ERR_USAGE, "Please specify a `--team-id <integer>`")
		}

		validateTeamID(db, argTeamID)

		if !utils.RegisterAgent(db, argRegisterAgentUUID, argTeamID) {
			os.Exit(utils.ERR_GENERIC)
		}
		os.Exit(utils.EXIT_SUCCESS)
	}

	// If this is reached, no command-line flag (action) has been specified.
	// Print usage
	utils.LogPlain(utils.Warning, "Please specify an action")
	utils.MapTypesToColor[utils.Debug].Println("------------------------------------------------------------")
	flag.Usage()
	utils.MapTypesToColor[utils.Debug].Println("------------------------------------------------------------")
}
