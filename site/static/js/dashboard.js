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
	let teamName = document.getElementById("teamName")
	teamName.innerHTML = userJwt.teamName

	let slider = document.getElementById("callbackSlider")
	let minutes = document.getElementById("minutes")
	let minutesText = document.getElementById("minutesText")
	let weight = document.getElementById("callbackWeight")

	slider.addEventListener("input", (event) => {
		minutes.innerHTML = event.target.value
		minutesText.innerHTML = event.target.value > 1 ? "minutes" : "minute"
		weight.innerHTML = calculateWeight(event.target.value)
	})
})