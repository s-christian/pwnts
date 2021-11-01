function setCookie(cname, cvalue) {
	const now = new Date()
	now.setTime(now.getTime() + (365 * 24 * 60 * 60 * 1000)) // cookies set to expire in one year
	const expires = "expires=" + now.toUTCString()
	document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/;secure"
}

function getCookie(cname) {
	const name = cname + "=";
	const decodedCookie = decodeURIComponent(document.cookie)
	const values = decodedCookie.split(";")
	for (let i = 0; i < values.length; i++) {
		let c = values[i]
		while (c.charAt(0) == ' ') {
			c = c.substring(1);
		}
		if (c.indexOf(name) == 0) {
			return c.substring(name.length, c.length)
		}
	}
	return ""
}