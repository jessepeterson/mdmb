package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	var (
		dbPath = f.String("db", "mdmb.db", "mdmb database file path")
	)
	f.Usage = func() {
		fmt.Fprintf(f.Output(), "%s [flags] <subcommand> [flags]\n", f.Name())
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
	f := flag.NewFlagSet("enroll", flag.ExitOnError)
	var (
		enrollType = f.String("type", "profile", "enrollment type")
		number     = f.Int("n", 1, "number of devices")
	)
	f.Usage = func() {
		mainUsage()
		fmt.Fprintf(f.Output(), "\n%s subcommand flags:\n", f.Name())
		f.PrintDefaults()
	}
	f.Parse(args)

	fmt.Printf("enrollment type: %s\nnumber: %d\n", *enrollType, *number)
}
