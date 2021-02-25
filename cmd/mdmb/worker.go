package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jessepeterson/mdmb/internal/device"
	"github.com/jessepeterson/mdmb/internal/mdmclient"
)

type ConnectWorkerData struct {
	Device    *device.Device
	MDMClient *mdmclient.MDMClient
}

func ConnectWork(cwd *ConnectWorkerData) {
	if cwd.MDMClient == nil || cwd.Device == nil {
		log.Println("invalid device connect work")
		return
	}
	log.Printf("device %s connecting to MDM", cwd.Device.UDID)
	err := cwd.MDMClient.Connect()
	if err != nil {
		log.Println(fmt.Errorf("device connect for device %s: %w", cwd.Device.UDID, err))
	}
}

func PooledConnectWork(cwds []*ConnectWorkerData, workers, iterations int) {
	var wg sync.WaitGroup
	queue := make(chan *ConnectWorkerData, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cwd := range queue {
				ConnectWork(cwd)
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
	log.Printf("took %s\n", time.Since(start))
}
