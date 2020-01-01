package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	f := flag.NewFlagSet("", flag.ExitOnError)
	var (
		dbPath = f.String("db", "mdmb.db", "mdmb database file path")
	)
	f.Usage = func() {
		fmt.Fprintf(f.Output(), "%s [flags] <subcommand> [flags]\n", os.Args[0])
		fmt.Fprint(f.Output(), "\nFlags:\n")
		f.PrintDefaults()
		fmt.Fprint(f.Output(), "\nSubcommands:\n")
		fmt.Fprintln(f.Output(), "    enroll\tenroll devices into MDM")
	}
	f.Parse(os.Args[1:])

	if len(f.Args()) < 1 {
		fmt.Fprintln(f.Output(), "no subcommand supplied")
		f.Usage()
		os.Exit(2)
	}

	switch f.Args()[0] {
	case "enroll":
		enroll(f.Args()[1:], *dbPath, f.Usage)
	default:
		fmt.Fprintf(f.Output(), "invalid subcommand: %s\n", f.Args()[0])
		f.Usage()
		os.Exit(2)
	}
}

func enroll(args []string, _ string, mainUsage func()) {
	f := flag.NewFlagSet("", flag.ExitOnError)
	var (
		enrollType = f.String("type", "profile", "enrollment type")
	)
	f.Usage = func() {
		mainUsage()
		fmt.Fprint(f.Output(), "\nenroll subcommand flags:\n")
		f.PrintDefaults()
	}
	f.Parse(args)

	fmt.Printf("enrollment type: %s\n", *enrollType)
}
