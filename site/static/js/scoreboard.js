function updateScoreboard() {
	const scoreboardRequest = new XMLHttpRequest()

	// Define what happens on successful data submission
	scoreboardRequest.addEventListener("load", (event) => {
		try {
			// Must parse twice. I guess it's too stringy.
			let scoreboardData = JSON.parse(JSON.parse(event.target.responseText))
			populateScoreboard(scoreboardData)
		} catch(e) {
			console.error("Failed to parse retrieved scoreboard data as JSON")
		}
	})
	
	// Define what happens in case of error
	scoreboardRequest.addEventListener("error", (event) => {
		console.error("Failed to retrieve scoreboard data")
	})
	
	// Set up the request
	scoreboardRequest.open("GET", "/api/scoreboard")

	// Send the request
	scoreboardRequest.send()
}

function populateScoreboard(data) {
	scoreboardBody = document.getElementById("scoreboard").getElementsByTagName("tbody")[0]

	newTableData = ""
	for (let team in data) {
		/*
			Although the Go backend automatically escapes HTML tags, ensure that
			the team name retrieved from the raw API data can't insert arbitrary
			HTML or XSS.

			Render all characters as plain text. Trick from:
			https://stackoverflow.com/a/9251169
		*/
		let escape = document.createElement("textarea")
		escape.textContent = team
		escapedTeam = escape.innerHTML

		newTableData += `
			<tr>
				<td class="tableTeam"><span>${escapedTeam}</span></td>
				<td class="tablePwnts">${data[team].pwnts}</td>
				<td class="tablePwns">${data[team].pwned_hosts}</td>
			</tr>
		`
	}

	scoreboardBody.innerHTML = newTableData
}

// *** Refresh the scoreboard every five seconds via AJAX
document.addEventListener("DOMContentLoaded", () => {
	setInterval(() => {
		updateScoreboard()
	}, 5000)
})