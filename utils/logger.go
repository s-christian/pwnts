package utils

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

type logType int

const (
	Error   logType = 0
	Warning logType = 1
	Info    logType = 2
	List    logType = 3
	Done    logType = 4
	Debug   logType = 5

	EXIT_SUCCESS int = 0
	ERR_GENERIC  int = 1

	ERR_USAGE     int = 10
	ERR_INPUT     int = 11
	ERR_UUID      int = 12
	ERR_FILE_READ int = 13

	ERR_CONNECTION int = 30
	ERR_WRITE      int = 31
	ERR_BYTES      int = 32
)

var MapTypesToColor = map[logType]*color.Color{
	Error:   color.New(color.Bold, color.FgRed),
	Warning: color.New(color.Bold, color.FgYellow),
	Info:    color.New(color.Bold, color.FgCyan),
	List:    color.New(color.Bold, color.FgBlue),
	Done:    color.New(color.Bold, color.FgGreen),
	Debug:   color.New(color.Bold, color.FgMagenta),
}

var MapTypesToPrefix = map[logType]string{
	Error:   MapTypesToColor[Error].Sprint("[!]"),
	Warning: MapTypesToColor[Warning].Sprint("[-]"),
	Info:    MapTypesToColor[Info].Sprint("[*]"),
	List:    MapTypesToColor[List].Sprint("[^]"),
	Done:    MapTypesToColor[Done].Sprint("[+]"),
	Debug:   MapTypesToColor[Debug].Sprint("[?]"),
}

// Log a timestamped message with a given logType
func Log(messageType logType, messages ...string) {
	fmt.Printf("%s (%s)\t%s\n",
		MapTypesToPrefix[messageType],
		time.Now().Format(time.RFC3339Nano),
		MapTypesToColor[messageType].Sprint(strings.Join(messages, " ")),
	)
}

// Return the log string instead of printing it
func LogReturn(messageType logType, messages ...string) string {
	return fmt.Sprintf("%s (%s)\t%s",
		MapTypesToPrefix[messageType],
		time.Now().Format(time.RFC3339Nano),
		MapTypesToColor[messageType].Sprint(strings.Join(messages, " ")),
	)
}

// Log the message, then print the error string
func LogError(messageType logType, err error, messages ...string) {
	Log(messageType, messages...)
	fmt.Printf("\t\t\t\t\t\t%s\n",
		MapTypesToColor[messageType].Sprint(err.Error()),
	)
}

func CheckError(messageType logType, err error, messages ...string) bool {
	if err != nil {
		LogError(messageType, err, messages...)
		return true
	}
	return false
}

// Same as CheckError() but exit on error
func CheckErrorExit(messageType logType, err error, errCode int, messages ...string) {
	if CheckError(messageType, err, messages...) {
		os.Exit(errCode)
	}
	// otherwise continue
}
