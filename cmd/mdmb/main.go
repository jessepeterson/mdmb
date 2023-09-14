package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jessepeterson/mdmb/internal/attest"
	"github.com/jessepeterson/mdmb/internal/device"
	bolt "go.etcd.io/bbolt"
)

var version = "unknown"

type subCmdFn func(string, []string, RunContext, func())

type subCmd struct {
	Name        string
	Description string
	Func        subCmdFn
}

func help(_ string, _ []string, _ RunContext, usage func()) {
	usage()
}

// RunContext contains "global" runtime environment settings
type RunContext struct {
	DB *bolt.DB
	// device UUIDs (UDIDs)
	UUIDs []string
}

func main() {
	var subCmds []subCmd = []subCmd{
		{"help", "Display usage help", help},
		{"devices-list", "list created devices", devicesList},
		{"devices-create", "create new devices", devicesCreate},
		{"devices-connect", "devices connect to MDM", devicesConnect},
		{"devices-tokenupdate", "send another tokenupdate to MDM server", devicesTokenUpdate},
		{"devices-profiles-list", "list device profiles", devicesProfilesList},
		{"devices-profiles-install", "install profiles onto device (i.e. enroll)", devicesProfilesInstall},
		{"devices-profiles-remove", "remove profiles from device", devicesProfilesRemove},
		{"devices-mdm-signature", "Print Mdm-Signature header for device", devicesMdmSignature},
		{"version", "display version", versionSubCmd},
	}
	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	var (
		dbPath = f.String("db", "mdmb.db", "mdmb database file path")
		uuids  = f.String("uuids", "", "comma-separated list of device UUIDs, '-' to read from stdin, or 'all' for all devices")
	)
	f.Usage = func() {
		fmt.Fprintf(f.Output(), "%s [flags] <subcommand> [flags]\n", f.Name())
		fmt.Fprint(f.Output(), "\nFlags:\n")
		f.PrintDefaults()
		fmt.Fprint(f.Output(), "\nSubcommands:\n")
		w := tabwriter.NewWriter(f.Output(), 4, 4, 4, ' ', 0)
		for _, sc := range subCmds {
			fmt.Fprintf(w, "\t%s\t%s\n", sc.Name, sc.Description)
		}
		w.Flush()
	}
	f.Parse(os.Args[1:])

	if len(f.Args()) < 1 {
		fmt.Fprintln(f.Output(), "no subcommand supplied")
		f.Usage()
		os.Exit(2)
	}

	db, err := bolt.Open(*dbPath, 0644, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	mathrand.Seed(time.Now().UnixNano())

	rctx := RunContext{DB: db}

	if *uuids != "" {
		if *uuids == "all" {
			var err error
			rctx.UUIDs, err = device.List(rctx.DB)
			if err != nil {
				log.Fatal(err)
			}
		} else if *uuids == "-" {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				rctx.UUIDs = append(rctx.UUIDs, scanner.Text())
			}
			if err := scanner.Err(); err != nil {
				log.Fatal(err)
			}
		} else {
			rctx.UUIDs = strings.Split(*uuids, ",")
		}
	}

	for _, sc := range subCmds {
		if f.Args()[0] == sc.Name {
			sc.Func(sc.Name, f.Args()[1:], rctx, f.Usage)
			return
		}
	}

	fmt.Fprintf(f.Output(), "invalid subcommand: %s\n", f.Args()[0])
	f.Usage()
	os.Exit(2)
}

func setSubCommandFlagSetUsage(f *flag.FlagSet, usage func()) {
	f.Usage = func() {
		usage()
		fmt.Fprintf(f.Output(), "\nFlags for %s subcommand:\n", f.Name())
		f.PrintDefaults()
	}
}

func checkDeviceUUIDs(rctx RunContext, requireEmpty bool, subCmdName string) error {
	if requireEmpty && len(rctx.UUIDs) != 0 {
		return errors.New("cannot supply UUIDs for " + subCmdName)
	} else if !requireEmpty && len(rctx.UUIDs) < 1 {
		return errors.New("no device UUIDs supplied, use -uuids argument for " + subCmdName)
	}
	return nil
}

func devicesProfilesInstall(name string, args []string, rctx RunContext, usage func()) {
	f := flag.NewFlagSet(name, flag.ExitOnError)
	var (
		file                     = f.String("f", "", "profile to install")
		attestationCACertFile    = f.String("cert", "", "Path to the fake attestation CA certificate in PEM format")
		attestationCAKeyFile     = f.String("key", "", "Path to the fake attestation CA private key")
		attestationCAKeyPassword = f.String("pass", "", "Password for the fake attestation CA private key")
	)
	setSubCommandFlagSetUsage(f, usage)
	f.Parse(args)

	if *file == "" {
		fmt.Fprintln(f.Output(), "must specify profile")
		f.Usage()
		os.Exit(2)
	}

	aca, err := attest.New(*attestationCACertFile, *attestationCAKeyFile, *attestationCAKeyPassword)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	ctx = attest.Context(ctx, aca)

	ep, err := ioutil.ReadFile(*file)
	if err != nil {
		log.Fatal(err)
	}

	err = checkDeviceUUIDs(rctx, false, name)
	if err != nil {
		log.Fatal(err)
	}

	for _, u := range rctx.UUIDs {
		fmt.Println(u)
		dev, err := device.Load(u, rctx.DB)
		if err != nil {
			log.Println(err)
			continue
		}

		err = dev.InstallProfile(ctx, ep)
		if err != nil {
			log.Println(err)
			continue
		}
	}
}

func devicesList(name string, args []string, rctx RunContext, usage func()) {
	err := checkDeviceUUIDs(rctx, true, name)
	if err != nil {
		log.Fatal(err)
	}

	uuids, err := device.List(rctx.DB)
	if err != nil {
		log.Fatal(err)
	}

	for _, v := range uuids {
		fmt.Println(v)
	}
}

func devicesCreate(name string, args []string, rctx RunContext, usage func()) {
	f := flag.NewFlagSet(name, flag.ExitOnError)
	var (
		number = f.Int("n", 1, "number of devices")
	)
	setSubCommandFlagSetUsage(f, usage)
	f.Parse(args)

	err := checkDeviceUUIDs(rctx, true, name)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("creating %d device(s)\n", *number)
	for i := 0; i < *number; i++ {
		d := device.New("", rctx.DB)
		err := d.Save()
		if err != nil {
			log.Fatal(err)
			continue
		}

		fmt.Println(d.UDID)
	}

}

func devicesTokenUpdate(name string, args []string, rctx RunContext, usage func()) {
	f := flag.NewFlagSet(name, flag.ExitOnError)
	var (
		number = f.String("addl", "", "additional text inside token update values")
	)
	setSubCommandFlagSetUsage(f, usage)
	f.Parse(args)

	err := checkDeviceUUIDs(rctx, false, name)
	if err != nil {
		log.Fatal(err)
	}

	for _, u := range rctx.UUIDs {
		fmt.Println(u)

		dev, err := device.Load(u, rctx.DB)
		if err != nil {
			log.Println(err)
			continue
		}

		client, err := dev.MDMClient()
		if err != nil {
			log.Println(err)
			continue
		}

		err = client.TokenUpdate(*number)
		if err != nil {
			log.Println(err)
		}
	}
}

func devicesConnect(name string, args []string, rctx RunContext, usage func()) {
	f := flag.NewFlagSet(name, flag.ExitOnError)
	var (
		workers    = f.Int("w", 1, "number of workers (concurrency)")
		iterations = f.Int("i", 1, "number of iterations of connects")
	)
	setSubCommandFlagSetUsage(f, usage)
	f.Parse(args)

	err := checkDeviceUUIDs(rctx, false, name)
	if err != nil {
		log.Fatal(err)
	}

	workerData := []*ConnectWorkerData{}

	for _, u := range rctx.UUIDs {
		dev, err := device.Load(u, rctx.DB)
		if err != nil {
			log.Println(err)
			continue
		}

		client, err := dev.MDMClient()
		if err != nil {
			log.Println(err)
			continue
		}

		workerData = append(workerData, &ConnectWorkerData{
			Device:    dev,
			MDMClient: client,
		})
	}

	startConnectWorkers(workerData, *workers, *iterations)
}

func devicesProfilesList(name string, args []string, rctx RunContext, usage func()) {
	err := checkDeviceUUIDs(rctx, false, name)
	if err != nil {
		log.Fatal(err)
	}

	for _, u := range rctx.UUIDs {
		fmt.Printf("profiles for UUID: %s\n", u)
		dev, err := device.Load(u, rctx.DB)
		if err != nil {
			log.Println(err)
			continue
		}

		profileUUIDs, err := dev.SystemProfileStore().ListUUIDs()
		if err != nil {
			log.Println(err)
			continue
		}
		for _, uuid := range profileUUIDs {
			fmt.Println(uuid)
		}
	}
}

func devicesMdmSignature(name string, args []string, rctx RunContext, usage func()) {
	f := flag.NewFlagSet(name, flag.ExitOnError)
	var (
		file = f.String("f", "", "path to file to sign")
	)
	setSubCommandFlagSetUsage(f, usage)
	f.Parse(args)

	if *file == "" {
		fmt.Fprintln(f.Output(), "must specify profile")
		f.Usage()
		os.Exit(2)
	}

	err := checkDeviceUUIDs(rctx, false, name)
	if err != nil {
		log.Fatal(err)
	}

	fileBytes, err := os.ReadFile(*file)
	if err != nil {
		log.Fatal(err)
	}

	for _, u := range rctx.UUIDs {
		dev, err := device.Load(u, rctx.DB)
		if err != nil {
			log.Println(err)
			continue
		}

		client, err := dev.MDMClient()
		if err != nil {
			log.Println(err)
			continue
		}

		sig, err := client.MdmSignature(fileBytes)
		if err != nil {
			log.Println(err)
			continue
		}

		if len(rctx.UUIDs) > 1 {
			fmt.Printf("%s\t%s\n", dev.UDID, sig)
		} else {
			fmt.Println(sig)
		}
	}
}

func devicesProfilesRemove(name string, args []string, rctx RunContext, usage func()) {
	f := flag.NewFlagSet(name, flag.ExitOnError)
	var (
		id = f.String("i", "", "profile identifier")
	)
	setSubCommandFlagSetUsage(f, usage)
	f.Parse(args)

	if *id == "" {
		fmt.Fprintln(f.Output(), "must specify profile identifier")
		f.Usage()
		os.Exit(2)
	}

	err := checkDeviceUUIDs(rctx, false, name)
	if err != nil {
		log.Fatal(err)
	}

	for _, u := range rctx.UUIDs {
		fmt.Println(u)
		dev, err := device.Load(u, rctx.DB)
		if err != nil {
			log.Println(err)
			continue
		}

		err = dev.RemoveProfile(*id)
		if err != nil {
			log.Println(err)
			continue
		}
	}
}

func versionSubCmd(_ string, _ []string, _ RunContext, _ func()) {
	fmt.Println(version)
}
