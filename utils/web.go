package utils

import (
	"fmt"
	"net/http"
)

// Handle any errors encountered when trying to serve a web page
func CheckWebError(writer http.ResponseWriter, request *http.Request, err error, errorMessage string, functionName string) bool {
	if CheckError(Error, err, errorMessage) {
		_, err := fmt.Fprint(writer, "Could not serve '"+request.Method+" "+request.URL.RequestURI()+"'")
		CheckError(Error, err, functionName+": Couldn't write to http.ResponseWriter")
		return true
	}
	return false
}
