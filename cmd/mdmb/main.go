package main

import (
	"flag"
	"fmt"
	"os"
)

func commonUsage() {
	flag.PrintDefaults()
}

func main() {
	args := os.Args[1:]
	commonFlags := flag.NewFlagSet("", flag.ExitOnError)
	commonFlags.Usage = func() {
		fmt.Fprintf(commonFlags.Output(), "%s [flags] <subcommand> [flags]\n\n", os.Args[0])
		commonFlags.PrintDefaults()
		fmt.Fprint(commonFlags.Output(), "\nvalid subcommands:\n\n")
		fmt.Fprintf(commonFlags.Output(), "\tenroll\n")
	}
	commonFlags.Parse(args)

	args = args[len(args)-commonFlags.NArg():]
	if len(args) < 1 {
		fmt.Fprintln(commonFlags.Output(), "missing subcommand")
		commonFlags.Usage()
		os.Exit(1)
	}
	switch args[0] {
	case "enroll":
		enrollCmd(args[1:])
	default:
		fmt.Fprintf(commonFlags.Output(), "invalid subcommand: %s\n", args[0])
		commonFlags.Usage()
		os.Exit(1)
	}
}
