package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gopkg.in/yaml.v2"
	"log"
	"os"
	"time"
)

type PortConfig struct {
	Ports []int `yaml:"ports"`
}

func readConfig() (*PortConfig, error) {
	config := &PortConfig{}
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func createBpfFilter(ports []int) string {
	filter := fmt.Sprintf("port %d", ports[0])
	for i := 1; i < len(ports); i++ {
		filter += fmt.Sprintf(" or port %d", ports[i])
	}
	return filter
}

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for _, device := range devices {
		fmt.Printf("Name: %s, Description: %s\n", device.Name, device.Description)
	}

	ports, err := readConfig()
	if err != nil {
		log.Fatal(err)
	}

	handle, err := pcap.OpenLive("\\Device\\NPF_Loopback", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	portDurationUsage := make(map[int]int64)
	portTotalUsage := make(map[int]int64)
	for _, port := range ports.Ports {
		portDurationUsage[port] = 0
		portTotalUsage[port] = 0
	}

	duration := 1 * time.Minute
	elapsed := 0 * time.Minute
	ticker := time.NewTicker(duration)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			for port, dataUsed := range portDurationUsage {
				fmt.Printf("%d port used in %v: %d bytes / %d bytes\n", port, elapsed, dataUsed, portTotalUsage[port])
				elapsed += 1 * time.Minute
				portDurationUsage[port] = 0
			}
		}
	}()

	bpfFilter := createBpfFilter(ports.Ports)

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		log.Fatalf("setting BPF filter: %v", err)
	}
	fmt.Println("set filter: ", bpfFilter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			packetSize := int64(len(packet.Data()))

			if int(tcp.SrcPort) != 0 && contains(ports.Ports, int(tcp.SrcPort)) {
				portDurationUsage[int(tcp.SrcPort)] += packetSize
				portTotalUsage[int(tcp.SrcPort)] += packetSize
			}
			if int(tcp.DstPort) != 0 && contains(ports.Ports, int(tcp.DstPort)) {
				portDurationUsage[int(tcp.DstPort)] += packetSize
				portTotalUsage[int(tcp.DstPort)] += packetSize
			}
		}
	}
}

func contains(arr []int, target int) bool {
	for _, item := range arr {
		if item == target {
			return true
		}
	}
	return false
}
