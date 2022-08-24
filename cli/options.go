package cli

import (
	"ffsyncclient/consts"
	"ffsyncclient/utils/term"
	"time"
)

type Options struct {
	Quiet                bool
	Verbose              bool
	Format               *OutputFormat
	SessionFilePath      string
	AuthServerURL        string
	TokenServerURL       string
	OutputColor          bool
	OutputFile           *string
	TimeZone             *time.Location
	TimeFormat           string
	SaveRefreshedSession bool
}

func DefaultCLIOptions() Options {
	return Options{
		Quiet:                false,
		Verbose:              false,
		Format:               nil,
		SessionFilePath:      "~/.config/firefox-sync-client.secret",
		AuthServerURL:        consts.ServerURLProduction,
		TokenServerURL:       consts.TokenServerURL,
		OutputColor:          term.TermSupportsColors(),
		TimeZone:             time.Local,
		TimeFormat:           "2006-01-02 15:04:05Z07:00",
		OutputFile:           nil,
		SaveRefreshedSession: true,
	}
}
