package main

import (
	"flag"
	"fmt"
	"os"
)

func cmdUnpin(args []string) {
	fs := flag.NewFlagSet("unpin", flag.ExitOnError)
	pinPath := fs.String("pin-path", defaultPinPath, pinPathHelp)
	yes := fs.Bool("yes", false, "confirm: this drops every active session")
	_ = fs.Parse(args)

	if !*yes {
		fmt.Fprintf(os.Stderr,
			"unpin removes %s, which drops the whitelist and forces every connected\n"+
				"player to reconnect. Stop the daemon first, then re-run with --yes.\n", *pinPath)
		os.Exit(2)
	}
	if err := os.RemoveAll(*pinPath); err != nil {
		fmt.Fprintln(os.Stderr, "unpin:", err)
		os.Exit(1)
	}
	fmt.Printf("removed %s\n", *pinPath)
}
