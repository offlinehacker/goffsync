package syncclient

import (
	"runtime"
	"strconv"
	"strings"
)

// LogFunc is a configurable logging function that can be set to enable debug logging.
// It takes filename, function name, message, and optional key-value pairs as arguments.
var LogFunc func(filename, funcname, msg string, keysAndVals ...any)

func debug(msg string, keysAndVals ...any) {
	if LogFunc == nil {
		return
	}

	pc, file, line, ok := runtime.Caller(1)
	if !ok {
		return
	}

	fileName := file[strings.LastIndex(file, "/")+1:] + ":" + strconv.Itoa(line)
	funcName := runtime.FuncForPC(pc).Name()

	LogFunc(fileName, funcName, msg, keysAndVals...)
}
