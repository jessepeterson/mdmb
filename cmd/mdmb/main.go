package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"os"
	"text/tabwriter"
	"time"

	"github.com/jessepeterson/mdmb/internal/device"
	"github.com/jessepeterson/mdmb/internal/keychain"
	"github.com/jessepeterson/mdmb/internal/mdmclient"
	"github.com/jessepeterson/mdmb/internal/profiles"
	bolt "go.etcd.io/bbolt"
)

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
}

func main() {
	var subCmds []subCmd = []subCmd{
		{"help", "Display usage help", help},
		{"devices-list", "list created devices", devicesList},
		{"devices-create", "create new devices", devicesCreate},
		{"devices-enroll", "enroll devices into MDM", devicesEnroll},
		{"devices-connect", "devices connect to MDM", devicesConnect},
	}
	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	var (
		dbPath = f.String("db", "mdmb.db", "mdmb database file path")
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

func devicesEnroll(name string, args []string, rctx RunContext, usage func()) {
	f := flag.NewFlagSet(name, flag.ExitOnError)
	var (
		file = f.String("file", "", "file of enrollment spec (e.g. profile)")
	)
	setSubCommandFlagSetUsage(f, usage)
	f.Parse(args)

	if *file == "" {
		fmt.Fprintln(f.Output(), "must specify enrollment profile")
		f.Usage()
		os.Exit(2)
	}

	ep, err := ioutil.ReadFile(*file)
	if err != nil {
		log.Fatal(err)
	}

	udids, err := device.List(rctx.DB)
	if err != nil {
		log.Fatal(err)
	}

	for _, u := range udids {
		dev, err := device.Load(u, rctx.DB)
		if err != nil {
			log.Println(err)
			continue
		}

		fmt.Println(dev.UDID)

		// create reference to this device's system keychain
		kc := keychain.New(dev.UDID, keychain.KeychainSystem, rctx.DB)

		ps := profiles.New(dev.UDID, rctx.DB)

		client, err := mdmclient.NewMDMClient(dev, kc, ps)
		if err != nil {
			log.Println(err)
			continue
		}

		err = client.Enroll(ep, rand.Reader)
		if err != nil {
			log.Println(err)
			continue
		}

		err = dev.Save(rctx.DB)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func devicesList(name string, args []string, rctx RunContext, usage func()) {
	udids, err := device.List(rctx.DB)
	if err != nil {
		log.Fatal(err)
	}

	for _, v := range udids {
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

	fmt.Println(*number)
	for i := 0; i < *number; i++ {
		d := device.New("")
		err := d.Save(rctx.DB)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(d.UDID)
	}

}

func devicesConnect(name string, args []string, rctx RunContext, usage func()) {
	f := flag.NewFlagSet(name, flag.ExitOnError)
	var (
		workers    = f.Int("w", 1, "workers (concurrency)")
		iterations = f.Int("i", 1, "number of iterations of connects")
	)
	setSubCommandFlagSetUsage(f, usage)
	f.Parse(args)

	udids, err := device.List(rctx.DB)
	if err != nil {
		log.Fatal(err)
	}

	workerData := []*ConnectWorkerData{}

	for _, u := range udids {
		dev, err := device.Load(u, rctx.DB)
		if err != nil {
			log.Println(err)
			continue
		}

		// create reference to this device's system keychain
		kc := keychain.New(dev.UDID, keychain.KeychainSystem, rctx.DB)

		ps := profiles.New(dev.UDID, rctx.DB)

		client, err := mdmclient.NewMDMClient(dev, kc, ps)
		if err != nil {
			log.Println(err)
			continue
		}

		workerData = append(workerData, &ConnectWorkerData{
			Device:    dev,
			MDMClient: client,
		})
	}

	fmt.Printf("starting %d workers for %d iterations\n", *workers, *iterations)
	startConnectWorkers(workerData, *workers, *iterations)
}
