package utils

import (
	"fmt"
	"math"
	"net/http"
	"time"
)

const (
	maxCallbackTime time.Duration = 15 * time.Minute
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

func CalculateCallbackPoints(timeDifference time.Duration, targetValue int) int {
	// Only care about minutes, in cases where a callback might be 5 milliseconds off or something negligible we don't care about.
	// We don't want to round on minimum time, but rounding on maximum time is fine.
	// 14.50 => 15, 15.49 => 15
	if timeDifference.Round(time.Minute) > maxCallbackTime {
		return 1 // only 1 point
	}

	// Exponential decay in point value
	// 1.2^(-0.9(x-1))
	// 1 minute = 100 points, 5 minutes = 52 points, 10 minutes = 23 points, 15 minutes = 10 points
	// Since UNIX time is used, accuracy is down to the second
	// Score is calculated as minutes between callbacks
	const baseValue float64 = 1.2
	const decayValue float64 = -0.9
	return int(math.Round(float64(targetValue) * math.Pow(baseValue, (decayValue*(float64(timeDifference/time.Minute)-1)))))
}
