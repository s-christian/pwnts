function updateScoreboard() {
	const scoreboardRequest = new XMLHttpRequest()

	// Define what happens on successful data submission
	scoreboardRequest.addEventListener("load", (event) => {
		let scoreboardResponse
		try {
			scoreboardResponse = JSON.parse(event.target.responseText)
		} catch(e) {
			console.error("Failed to parse retrieved scoreboard data as JSON")
			return
		}

		console.log(scoreboardResponse)
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

// *** Refresh the scoreboard every five seconds via AJAX
document.addEventListener("DOMContentLoaded", () => {
	setInterval(() => {
		updateScoreboard()
	}, 5000)
})