function parseJwt(token) {
	let base64Url = token.split(".")[1]
	let base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/")
	let jsonPayload = decodeURIComponent(atob(base64).split("").map((c) => {
		return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2)
	}).join(""))

	return JSON.parse(jsonPayload)
}

function calculateWeight(minutes) {
	// Exponential decay in point value
	// 1.2^(-0.9(x-1))
	// 1 minute = 100 points, 5 minutes = 52 points, 10 minutes = 23 points, 15 minutes = 10 points
	// Since UNIX time is used, accuracy is down to the second
	// Score is calculated as minutes between callbacks
	const baseValue = 1.2
	const decayValue = -0.9
	return Math.round(baseValue**(decayValue*(minutes-1)) * 100) / 100
}

let userJwt = parseJwt(getCookie("auth"))

document.addEventListener("DOMContentLoaded", () => {
	/* --- Dynamic form content --- */
	// Insert team name
	let teamName = document.getElementById("teamName")
	teamName.innerHTML = userJwt.teamName

	// Display pwnts weight values for selected callback time
	let slider = document.getElementById("callbackSlider")
	let minutes = document.getElementById("minutes")
	let minutesText = document.getElementById("minutesText")
	let weight = document.getElementById("callbackWeight")

	slider.addEventListener("input", (event) => {
		minutes.innerHTML = event.target.value
		minutesText.innerHTML = event.target.value > 1 ? "minutes" : "minute"
		weight.innerHTML = calculateWeight(event.target.value)
	})


	/* --- Handle agent generation --- */
	const agentForm = document.forms["agent-form"]
	const agentFormStatus = document.getElementById("agent-form-status")

	agentForm.addEventListener("submit", (event) => {
		event.preventDefault()
		
		displayWait(agentFormStatus, "Please wait for your Agent to be generated...")

		// Using XMLHttpRequest() over Fetch() for older browser compatibility
		const agentRequest = new XMLHttpRequest()

		// Bind the FormData object and the form element
		const formData = new FormData(agentForm)
		
		// Validate input values
		portValue = formData.get("localPort")
		if (portValue < 1 || portValue > 65535) {
			displayError(agentFormStatus, "Port numbers must range between 1 and 65535")
			return
		}
		callbackValue = formData.get("callbackMins")
		if (callbackValue < 1 || callbackValue > 15) {
			displayError(agentFormStatus, "Callback rate must be between 1 and 15 minutes")
			return
		}
	  
		// Define what happens on successful data submission
		agentRequest.addEventListener("load", (event) => {
			let agentResponse
			try {
				agentResponse = JSON.parse(event.target.responseText)
			} catch(e) {
				displayError(agentFormStatus, "Internal error: server did not return JSON")
				return
			}

			if (agentResponse.error) { // response received, error
				displayError(agentFormStatus, agentResponse.message)
			} else if (!agentResponse.error) { // response received, success
				displaySuccess(agentFormStatus, agentResponse.message)
			} else { // no response received, unknown server error
				displayError(agentFormStatus, "Error communicating with server")
			}
		})
	  
		// Define what happens in case of error
		agentRequest.addEventListener("error", (event) => {
			displayError(agentFormStatus, "Oops! Something went wrong...")
		})
	  
		// Set up the request
		agentRequest.open("POST", "/dashboard")
	  
		// Send the request with the form values
		agentRequest.send(formData)
	})
})