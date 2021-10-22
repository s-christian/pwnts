package utils

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

type LOGTYPE int

const (
	Error   LOGTYPE = 0
	Warning LOGTYPE = 1
	Info    LOGTYPE = 2
	List    LOGTYPE = 3
	Done    LOGTYPE = 4
	Debug   LOGTYPE = 5

	EXIT_SUCCESS int = 0

	ERR_USAGE     int = 10
	ERR_INPUT     int = 11
	ERR_UUID      int = 12
	ERR_FILE_READ int = 13

	ERR_CONNECTION int = 30
	ERR_WRITE      int = 31
	ERR_BYTES      int = 32

	ERR_GENERIC int = 50
)

var mapTypesToColor = map[LOGTYPE]color.Attribute{
	Error:   color.FgRed,
	Warning: color.FgYellow,
	Info:    color.FgCyan,
	List:    color.FgBlue,
	Done:    color.FgGreen,
	Debug:   color.FgMagenta,
}

var mapTypesToPrefix = map[LOGTYPE]string{
	Error:   color.New(color.Bold, mapTypesToColor[Error]).Sprint("[!]"),
	Warning: color.New(color.Bold, mapTypesToColor[Warning]).Sprint("[-]"),
	Info:    color.New(color.Bold, mapTypesToColor[Info]).Sprint("[*]"),
	List:    color.New(color.Bold, mapTypesToColor[List]).Sprint("[^]"),
	Done:    color.New(color.Bold, mapTypesToColor[Done]).Sprint("[+]"),
	Debug:   color.New(color.Bold, mapTypesToColor[Debug]).Sprint("[?]"),
}

func Log(logType LOGTYPE, messages ...string) {
	fmt.Printf("%s (%s)\t%s\n",
		mapTypesToPrefix[logType],
		time.Now().Format(time.RFC3339Nano),
		color.New(color.Bold, mapTypesToColor[logType]).Sprint(strings.Join(messages, " ")),
	)
}

func LogReturn(logType LOGTYPE, messages ...string) string {
	return fmt.Sprintf("%s (%s)\t%s",
		mapTypesToPrefix[logType],
		time.Now().Format(time.RFC3339Nano),
		color.New(color.Bold, mapTypesToColor[logType]).Sprint(strings.Join(messages, " ")),
	)
}

func LogError(logType LOGTYPE, err error, messages ...string) {
	Log(logType, messages...)
	fmt.Printf("\t\t\t\t\t\t%s\n",
		color.New(color.Bold, mapTypesToColor[logType]).Sprint(err.Error()),
	)
}

func CheckError(logType LOGTYPE, err error, messages ...string) bool {
	if err != nil {
		LogError(logType, err, messages...)
		return true
	}
	return false
}

// Same as CheckError() but exit on error
func CheckErrorExit(logType LOGTYPE, err error, errCode int, messages ...string) {
	if CheckError(logType, err, messages...) {
		os.Exit(errCode)
	}
	// otherwise continue
}
