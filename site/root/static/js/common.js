document.addEventListener("DOMContentLoaded", () => {
	/* --- Functions for options --- */
	function stopScanlines() {
		const scanlinesStylesheet = document.getElementById("scanlinesStylesheet")
		scanlinesStylesheet.disabled = true
	}
	function startScanlines() {
		const scanlinesStylesheet = document.getElementById("scanlinesStylesheet")
		scanlinesStylesheet.disabled = false
	}

	let fadeInInterval
	function stopAudio(audio) {
		clearInterval(fadeInInterval)
		audio.pause()
		audio.currentTime = 0
	}
	function fadeInAudio(audio, fadeStart) {
		stopAudio(audio)
		audio.volume = 0
		audio.play()

		fadeInInterval = setInterval(() => {
			// Start fading in half a second before the intro voice ends
			if ((audio.currentTime >= fadeStart) && (audio.volume < 1.0)) {
				audio.volume += 0.1
			}
			// When volume reaches 1 (max) stop the interval
			if (audio.volume >= 0.99999) { // it never reaches 1.0 for some reason, just 0.999...
				clearInterval(fadeInInterval)
			}
		}, 200)
	}
	function startMusic() {
		fadeInAudio(bgm, 0)
	}

	async function sleep(time) {
		await new Promise((r) => setTimeout(r, time))
	}


	/* --- Play intro voice and fade in background music --- */
	const introVoice = document.getElementById("introVoice")
	introVoice.play()

	const bgm = document.getElementById("bgm")

	// Must wait for the audio's metadata to load before we can access its duration,
	// otherwise we get NaN
	introVoice.addEventListener("loadedmetadata", () => {
		fadeInAudio(bgm, introVoice.duration - 0.5)
	})


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


	/* --- Apply user options, read "options" cookie --- */
	let options = {}
	if (getCookie("options") !== "") {
		options = JSON.parse(getCookie("options"))

		if (options.scanlines === false) { // "true" is the default
			document.getElementsByName("scanlines").item(1).setAttribute("checked", true)
			stopScanlines()
		}

		if (options.bgm === false) { // "true" is the default
			document.getElementsByName("bgm").item(1).setAttribute("checked", true)
			// TODO: Figure out why music still plays regardless upon startup
			bgm.addEventListener("load", () => {
				stopAudio(bgm)
			})
		}
	}


	/* --- Handle newly-set options, set "options" cookie --- */
	document.addEventListener("click", (event) => {
		if (event.target.tagName !== "INPUT") return // we only care about when users click on the radio inputs
		// Otherwise, adjust the options and set the "options" cookie
		switch (event.target.name) {
			case "scanlines":
				if (event.target.value === "on") {
					options.scanlines = true
					startScanlines()
				} else {
					options.scanlines = false
					stopScanlines()
				}
				break
			case "bgm":
				if (event.target.value === "on") {
					options.bgm = true
					startMusic()
				} else {
					options.bgm = false
					stopAudio(bgm)
				}
				break
		}
		setCookie("options", JSON.stringify(options))
	})
})