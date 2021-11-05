package utils

import (
	"database/sql"
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
)

const (
	DatabaseFilename string = "pwnts.db" // default

	ERR_DATABASE_INVALID int = 20
	ERR_STATEMENT        int = 21
	ERR_QUERY            int = 22
	ERR_SCAN             int = 23
)

var (
	CurrentDirectory, _        = os.Getwd()
	DatabaseFilepath    string = CurrentDirectory + "/server/" + DatabaseFilename // default
)

func GetDatabaseHandle() *sql.DB {
	// Open database
	db, err := sql.Open("sqlite3", DatabaseFilepath) // "=" required instead of ":=" as to not declare a local `db` variable
	CheckErrorExit(Error, err, ERR_GENERIC, "Could not open sqlite database file \""+DatabaseFilepath+"\"")
	if db == nil {
		Log(Error, "db == nil, this should never happen")
		os.Exit(ERR_DATABASE_INVALID)
	} else {
		Log(Done, "Opened database file")
	}

	return db
}

// Count the number of tables in the database and ensure it equals the expected value.
// TODO: validate table names, not just number of tables.
func ValidateDatabase(db *sql.DB) bool {
	Log(Info, "Validating database")

	// sanity check
	if db == nil {
		Log(Error, "db is nil for some reason")
		os.Exit(ERR_DATABASE_INVALID)
	}

	err := db.Ping()
	CheckErrorExit(Error, err, ERR_CONNECTION, "Cannot connect to the database. Have you intialized the database with `go run site.go --init-db` yet?")

	// This query is equivalent to `.tables` within the sqlite CLI, according to
	// [this](https://sqlite.org/cli.html#querying_the_database_schema) documentation.
	// showTablesStatement, err := db.Prepare(`
	// 	SELECT name FROM sqlite_master
	// 		WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'
	// 	UNION ALL
	// 	SELECT name FROM sqlite_temp_master
	// 		WHERE type IN ('table','view')
	// 	ORDER BY 1;
	// `)
	// tableNames, err := db.Query(`
	// 	SELECT name FROM sqlite_master
	// 		WHERE type IN ('table') AND name NOT LIKE 'sqlite_%'
	// 	ORDER BY 1;
	// `)
	tableNames, err := db.Query(`
		SELECT name FROM sqlite_master
		WHERE type IN ('table') AND name NOT LIKE 'sqlite_%'
		ORDER BY 1
	`)
	CheckErrorExit(Error, err, ERR_QUERY, "Unable to query for table names")
	defer tableNames.Close()

	// Iterate over returned rows to count and print all table names
	var tableName string
	tableCounter := 0
	Log(Info, "Printing tables:")
	for tableNames.Next() {
		err = tableNames.Scan(&tableName)
		CheckErrorExit(Error, err, ERR_QUERY, "Could not scan row for table name")

		if tableName == "" {
			Log(Error, "Database appears to be empty (no tables!), please run `go run databaseTools.go --init-db` first")
			MapTypesToColor[List].Println("\t\t\t\t\t\t'" + tableName + "'")
			os.Exit(ERR_DATABASE_INVALID)
		} else {
			tableCounter++
			color.Yellow("\t\t\t\t\t\t" + tableName)
		}
	}

	// Ensure we have the correct number of tables
	numExpectedTables := 4
	if tableCounter == numExpectedTables {
		Log(Done, "Database validated")
		return true
	} else {
		Log(Error, "Database is missing", fmt.Sprint(numExpectedTables-tableCounter), "tables, please run `go run server.go --init-db`")
		return false
	}
}

// Same as `ValidateDatabase(db)`, but exit when invalid
func ValidateDatabaseExit(db *sql.DB) {
	if !ValidateDatabase(db) {
		os.Exit(ERR_DATABASE_INVALID)
	}
}

// Utiliy to close an object that implements the `io.Closer` interface.
// Used over `object.Close()` for automatic error checking.
func Close(closable io.Closer) {
	CheckError(Error, closable.Close(), "Failed to close")
}

// func CloseDatabase(db *sql.DB) {
// 	CheckError(Error, db.Close(), "Failed to close database connection")
// }

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

// If err != nil, database error.
//
// If err == nil and hash == "", user doesn't exist.
func GetUserPasswordHash(db *sql.DB, username string) (string, error) {
	var dbPasswordHash string

	getUserPasswordHashSQL := `
		SELECT password_hash
		FROM Teams
		WHERE name = ?
	`
	getUserPasswordHashStatement, err := db.Prepare(getUserPasswordHashSQL)
	if err != nil {
		return dbPasswordHash, err
	}

	passwordHashRow := getUserPasswordHashStatement.QueryRow(username)
	Close(getUserPasswordHashStatement)

	err = passwordHashRow.Scan(&dbPasswordHash)
	// We don't want to return an error if the user simply doesn't exist
	if err != nil && err != sql.ErrNoRows {
		return dbPasswordHash, err
	}

	return dbPasswordHash, nil // return hash; if hash == "", user doesn't exist
}
