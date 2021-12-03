const displayLoginError = (formStatus, errorMessage) => {
	formStatus.innerHTML = errorMessage
	formStatus.classList.add("formError")
	formStatus.classList.remove("formSuccess", "hidden")
}
const displayLoginSuccess = (formStatus, successMessage) => {
	formStatus.innerHTML = successMessage 
	formStatus.classList.add("formSuccess")
	formStatus.classList.remove("formError", "hidden")
}


/* --- Process login via AJAX request to receive JWT cookie and display any errors --- */
document.addEventListener("DOMContentLoaded", () => {
	const loginForm = document.forms["login-form"]
	const loginFormStatus = document.getElementById("login-form-status")

	loginForm.addEventListener("submit", (event) => {
		event.preventDefault()

		// Using XMLHttpRequest() over Fetch() for older browser compatibility
		const loginRequest = new XMLHttpRequest()

		// Bind the FormData object and the form element
		const formData = new FormData(loginForm)
		
		// Check for falsy input values (null, empty string (""), undefined)
		// meaning the user still needs to provide a username and/or password
		if (!formData.get("username") || !formData.get("password")) {
			displayLoginError(loginFormStatus, "Please supply values for username and password")
			return
		}
	  
		// Define what happens on successful data submission
		loginRequest.addEventListener("load", (event) => {
			loginResponse = JSON.parse(event.target.responseText)
			if (loginResponse.error) { // response received, login error
				displayLoginError(loginFormStatus, loginResponse.message)
			} else if (!loginResponse.error) { // response received, login success
				displayLoginSuccess(loginFormStatus, loginResponse.message)
				setTimeout(() => { window.location.href = "/dashboard" }, 1000)
			} else { // no response received, unknown server error
				displayLoginError(loginFormStatus, "Error communicating with server")
			}

			loginForm.reset() // clear form values
		})
	  
		// Define what happens in case of error
		loginRequest.addEventListener("error", (event) => {
			displayLoginError(loginFormStatus, "Oops! Something went wrong...")
		})
	  
		// Set up the request
		loginRequest.open("POST", "/login")
	  
		// The data sent is what the user provided in the form
		loginRequest.send(formData)
	})
})