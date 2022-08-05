package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	RootCmd = &cobra.Command{
		Use: "auth",
	}
)

func init() {
	RootCmd.AddCommand(serveCmd)
}

// Execute executes the root command
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
