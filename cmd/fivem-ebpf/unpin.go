package main

import (
	"flag"
	"fmt"
	"os"
)

type unpinOpts struct {
	pinPath string
	yes     bool
}

func parseUnpinFlags(args []string) (unpinOpts, error) {
	var o unpinOpts
	fs := flag.NewFlagSet("unpin", flag.ContinueOnError)
	fs.StringVar(&o.pinPath, "pin-path", defaultPinPath, pinPathHelp)
	fs.BoolVar(&o.yes, "yes", false, "confirm: this drops every active session")
	return o, fs.Parse(args)
}

func cmdUnpin(args []string) {
	o, err := parseUnpinFlags(args)
	if err != nil {
		exitFlagError(err)
	}

	if !o.yes {
		fmt.Fprintf(os.Stderr,
			"unpin removes %s, which drops the whitelist and forces every connected\n"+
				"player to reconnect. Stop the daemon first, then re-run with --yes.\n", o.pinPath)
		os.Exit(2)
	}
	if err := os.RemoveAll(o.pinPath); err != nil {
		fmt.Fprintln(os.Stderr, "unpin:", err)
		os.Exit(1)
	}
	fmt.Printf("removed %s\n", o.pinPath)
}
