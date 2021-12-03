package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/s-christian/pwnts/utils"
)

type TeamScores struct {
	Pwnts      int `json:"pwnts"`
	PwnedHosts int `json:"pwned_hosts"`
}

/*
	Retrieve the last two Agent checkins grouped by team and target IP address
*/
func GetScoreboardData(db *sql.DB) (data []byte, err error) {
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
	if utils.CheckError(utils.Error, err, "Could not create GetLastTwoCallbacks statement") {
		return
	}

	lastTwoCallbacksRows, err := getLastTwoCallbacksStatement.Query()
	if utils.CheckError(utils.Error, err, "Could not execute GetLastTwoCallbacks statement") {
		return
	}
	utils.Close(getLastTwoCallbacksStatement)

	/*
		--- Retrieve all team names and initialize the map ---
	*/
	teamNames, err := utils.GetTeamNames(db)
	if utils.CheckError(utils.Error, err, "Could not retrieve list of Team names") {
		return
	}

	teamsPointsAndHosts := make(map[string]*TeamScores, len(teamNames))
	for _, teamName := range teamNames {
		teamsPointsAndHosts[teamName] = &TeamScores{Pwnts: 0, PwnedHosts: 0}
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
		if utils.CheckError(utils.Error, lastTwoCallbacksRows.Err(), "Could not prepare next db row for scanning GetLastTwoCallbacks rows") {
			return
		}

		// team_id, target_ip_address, value, time_unix, callback_order (1 or 2, 1 being first and most recent)
		// Compare second callback to the most recent one
		var (
			dbTeamNameCurrent          string
			dbTargetIpAddressCurrent   string
			dbTargetValueCurrent       int
			dbAgentCallbackUnixCurrent int
			dbCallbackOrderCurrent     int
		)

		err = lastTwoCallbacksRows.Scan(&dbTeamNameCurrent, &dbTargetIpAddressCurrent, &dbTargetValueCurrent, &dbAgentCallbackUnixCurrent, &dbCallbackOrderCurrent)
		if utils.CheckError(utils.Error, err, "Could not scan GetLastTwoCallbacks rows") {
			return
		}

		if dbCallbackOrderCurrent == 1 {
			var checkinTimeAgo time.Duration = time.Duration(time.Now().Unix()-int64(dbAgentCallbackUnixCurrent)) * time.Second
			if checkinTimeAgo.Round(time.Second) > utils.MaxCallbackTime {
				agentDead = true
				continue // last callback was too long ago, assume Agent is dead
			}
			agentDead = false

			if singleCallback { // last row only had a single callback (the "pair" ended with callbackOrder == 1), add its points
				teamsPointsAndHosts[dbTeamNameLast].Pwnts += dbTargetValueLast // a single (Agent's first) callback will initially receive the full target value
				teamsPointsAndHosts[dbTeamNameLast].PwnedHosts++               // increment num of pwned hosts
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
			teamsPointsAndHosts[dbTeamNameCurrent].Pwnts += utils.CalculateCallbackPoints(checkinTimeDifference, dbTargetValueCurrent)
			teamsPointsAndHosts[dbTeamNameCurrent].PwnedHosts++
		} else {
			fmt.Println("I have no idea what happened:", dbCallbackOrderCurrent)
		}
	}
	utils.Close(lastTwoCallbacksRows)

	if singleCallback { // account for the very last row being a single callback
		teamsPointsAndHosts[dbTeamNameLast].Pwnts += dbTargetValueLast
		teamsPointsAndHosts[dbTeamNameLast].PwnedHosts++
	}

	data, err = json.Marshal(teamsPointsAndHosts)
	if utils.CheckError(utils.Error, err, "Could not marshal scoreboard data to JSON") {
		data, err = json.Marshal(errors.New("could not marshal data"))
	}

	return
}
