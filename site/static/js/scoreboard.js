async function updateScoreboard() {
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

async function populateScoreboard(data) {
	console.log(data)
	/*
	for (let team in data) {
		//console.log(data[team])
	}
	*/
}

// *** Refresh the scoreboard every five seconds via AJAX
document.addEventListener("DOMContentLoaded", () => {
	setInterval(() => {
		updateScoreboard()
	}, 5000)
})