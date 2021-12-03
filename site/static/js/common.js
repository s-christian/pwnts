// *** Functions for options
function disableScanlines() {
	scanlinesStylesheet = document.getElementById("scanlinesStylesheet").disabled = true
}
function enableScanlines() {
	scanlinesStylesheet = document.getElementById("scanlinesStylesheet").disabled = false
}

let fadeInInterval
const fadeStepMs = 200
function stopAudio(audio) {
	clearInterval(fadeInInterval)
	audio.pause()
	audio.currentTime = 0
}
function fadeInAudio(audio, fadeDelay) {
	stopAudio(audio)
	audio.volume = 0
	audio.play()

	fadeInInterval = setInterval(() => {
		// Start fading in half a second before the intro voice ends
		if ((audio.currentTime >= fadeDelay) && (audio.volume < 1.0)) {
			audio.volume += 0.1
		}
		// When volume reaches 1 (max) stop the interval
		if (audio.volume >= 0.99) { // it never reaches 1.0 for some reason, just 0.999...
			clearInterval(fadeInInterval)
		}
	}, fadeStepMs)
}

// *** Main content
document.addEventListener("DOMContentLoaded", () => {
	/* --- Apply user options, read "options" cookie --- */
	let playAudio = true
	let options = {}
	if (getCookie("options")) {
		options = JSON.parse(getCookie("options"))

		if (options.scanlines === false) { // default is "true"
			document.getElementById("scanlinesRadioOff").setAttribute("checked", true)
			disableScanlines()
		}

		if (options.bgm === false) { // default is "true"
			document.getElementById("bgmRadioOff").setAttribute("checked", true)
			playAudio = false
		}
	}


	/* --- Handle audio on page load --- */
	const bgm = document.getElementById("bgm")
	let introVoice
	if (playAudio) {
		// play intro voice if on front page (the only place page it's on)
		introVoice = document.getElementById("introVoice")
		if (introVoice) {
			introVoice.play()
			// Must wait for the audio's metadata to load before we can access
			// its duration, otherwise it's NaN
			introVoice.addEventListener("loadedmetadata", () => {
				fadeInAudio(bgm, introVoice.duration - 0.5)
			})
		} else {
			fadeInAudio(bgm, 0)
		}
	}


	/* --- Toggle options box visibility --- */
	const optionsHeader = document.getElementById("options-header")
	optionsHeader.addEventListener("click", () => {
		document.getElementById("options-close").classList.remove("hidden")
		document.getElementById("options-list").classList.remove("hidden")
		document.getElementById("options-header").classList.add("hidden")
	})

	const optionsX = document.getElementById("options-x")
	optionsX.addEventListener("click", () => {
		document.getElementById("options-header").classList.remove("hidden")
		document.getElementById("options-list").classList.add("hidden")
		document.getElementById("options-close").classList.add("hidden")
	})


	/* --- Handle newly-set options, set "options" cookie --- */
	document.addEventListener("click", (event) => {
		if (event.target.tagName !== "INPUT") return // we only care about when users click on the radio inputs

		// Otherwise, adjust the options and set the "options" cookie
		switch (event.target.name) {
			case "scanlinesRadio":
				if (event.target.value === "on") {
					options.scanlines = true
					enableScanlines()
				} else {
					options.scanlines = false
					disableScanlines()
				}
				break
			case "bgmRadio":
				if (event.target.value === "on") {
					options.bgm = true
					// only play if paused (don't restart already-playing audio)
					bgm.paused && fadeInAudio(bgm, 0)
				} else {
					options.bgm = false
					// only stop if currently playing (don't stop already-stopped audio)
					!bgm.paused && stopAudio(bgm)
				}
				break
		}

		setCookie("options", JSON.stringify(options))
	})
})