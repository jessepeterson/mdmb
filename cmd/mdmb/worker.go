package main

import (
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/jessepeterson/mdmb/internal/device"
)

type ConnectWorkerData struct {
	Device    *device.Device
	MDMClient *device.MDMClient
}

func connectWork(cwd *ConnectWorkerData) error {
	if cwd.MDMClient == nil || cwd.Device == nil {
		return errors.New("invalid mdm client or device")
	}
	return cwd.MDMClient.Connect()
}

func startConnectWorkers(cwds []*ConnectWorkerData, workers, iterations int) {
	var wg sync.WaitGroup
	queue := make(chan *ConnectWorkerData, workers)
	var (
		totalCt int
		errCt   int
		durrAcc time.Duration
		durrLow time.Duration
		durrHi  time.Duration
	)
	durrVals := make([]time.Duration, iterations*len(cwds))
	fmt.Printf("starting %d workers for %d iterations of %d devices (%d connects)\n", workers, iterations, len(cwds), len(cwds)*iterations)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cwd := range queue {
				totalCt++
				started := time.Now()
				err := connectWork(cwd)
				d := time.Since(started)
				durrVals[totalCt-1] = d
				if err != nil {
					errCt++
					fmt.Println()
					log.Println(fmt.Errorf("device connect for device %s: %w", cwd.Device.UDID, err))
					continue
				} else {
					fmt.Print(".")
				}
				durrAcc += d
				if durrLow == 0 {
					durrLow = d
				}
				if durrHi == 0 {
					durrHi = d
				}
				if d < durrLow {
					durrLow = d
				}
				if d > durrHi {
					durrHi = d
				}
			}
		}()
	}
	start := time.Now()
	for i := 0; i < iterations; i++ {
		for _, cwd := range cwds {
			queue <- cwd
		}
	}
	close(queue)
	wg.Wait()
	fmt.Print("\n\n")

	var durrSd float64
	var mean time.Duration
	var errors int
	if totalCt > 0 {
		mean = durrAcc / time.Duration(totalCt)
		errors = (errCt * 100) / totalCt
	}
	for _, v := range durrVals {
		durrSd += math.Pow(float64(v)-float64(mean), 2)
	}
	durrSd = math.Sqrt(durrSd / 10)

	w := tabwriter.NewWriter(os.Stdout, 4, 4, 4, ' ', 0)
	fmt.Fprintf(w, "Total MDM connects\t%d (%d%%)\n", totalCt, 100)
	fmt.Fprintf(w, "Errors\t%d (%d%%)\n", errCt, errors)
	fmt.Fprintf(w, "Total elapsed time\t%s\n", time.Since(start))
	fmt.Fprintf(w, "Min MDM connect elapsed\t%s\n", durrLow)
	fmt.Fprintf(w, "Max MDM connect elapsed\t%s\n", durrHi)
	fmt.Fprintf(w, "Avg (mean) MDM connect elapsed\t%s\n", mean)
	fmt.Fprintf(w, "Stddev MDM connect elapsed\t%s\n", time.Duration(durrSd))
	w.Flush()
}
