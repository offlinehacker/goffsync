package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ffsclient",
	Short: "FFSClient is a CLI for Firefox Sync",
	Long: `FFSClient is a command-line interface for interacting with Firefox Sync.
It allows you to manage bookmarks, passwords, and other synced data.`,
	Run: func(cmd *cobra.Command, args []string) {
		// This is called when the program is run without any subcommands
		fmt.Println("Welcome to FFSClient! Use --help for usage information.")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Here you can define flags and configuration settings for the root command
}
