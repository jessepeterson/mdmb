package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jessepeterson/mdmb/internal/device"
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
	DB    *bolt.DB
	UUIDs []string
}

func main() {
	var subCmds []subCmd = []subCmd{
		{"help", "Display usage help", help},
		{"devices-list", "list created devices", devicesList},
		{"devices-create", "create new devices", devicesCreate},
		{"devices-connect", "devices connect to MDM", devicesConnect},
		{"devices-profiles-list", "list device profiles", devicesProfilesList},
		{"devices-profiles-install", "install profiles onto device (i.e. enroll)", devicesProfilesInstall},
		{"devices-profiles-remove", "remove profiles from device", devicesProfilesRemove},
	}
	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	var (
		dbPath = f.String("db", "mdmb.db", "mdmb database file path")
		uuids  = f.String("uuids", "", "comma-separated list of device UUIDs")
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
		rctx.UUIDs = strings.Split(*uuids, ",")
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

func deviceUUIDs(rctx RunContext) ([]string, error) {
	if len(rctx.UUIDs) != 0 {
		return rctx.UUIDs, nil
	}
	return device.List(rctx.DB)
}

func devicesProfilesInstall(name string, args []string, rctx RunContext, usage func()) {
	f := flag.NewFlagSet(name, flag.ExitOnError)
	var (
		file = f.String("f", "", "profile to install")
	)
	setSubCommandFlagSetUsage(f, usage)
	f.Parse(args)

	if *file == "" {
		fmt.Fprintln(f.Output(), "must specify profile")
		f.Usage()
		os.Exit(2)
	}

	ep, err := ioutil.ReadFile(*file)
	if err != nil {
		log.Fatal(err)
	}

	udids, err := deviceUUIDs(rctx)
	if err != nil {
		log.Fatal(err)
	}

	for _, u := range udids {
		fmt.Println(u)
		dev, err := device.Load(u, rctx.DB)
		if err != nil {
			log.Println(err)
			continue
		}

		err = dev.InstallProfile(ep)
		if err != nil {
			log.Println(err)
			continue
		}
	}
}

func devicesList(name string, args []string, rctx RunContext, usage func()) {
	if len(rctx.UUIDs) > 0 {
		log.Fatal("cannot supply UUIDs for " + name)
	}

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

	if len(rctx.UUIDs) > 0 {
		log.Fatal("cannot supply UUIDs for " + name)
	}

	fmt.Println(*number)
	for i := 0; i < *number; i++ {
		d := device.New("", rctx.DB)
		err := d.Save()
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

	udids, err := deviceUUIDs(rctx)
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
	udids, err := deviceUUIDs(rctx)
	if err != nil {
		log.Fatal(err)
	}

	for _, u := range udids {
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
		fmt.Print(strings.Join(profileUUIDs, "\n"), "\n")
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

	udids, err := deviceUUIDs(rctx)
	if err != nil {
		log.Fatal(err)
	}

	for _, u := range udids {
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
