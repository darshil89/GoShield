package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/darshil89/firewall/api"
	"github.com/darshil89/firewall/types"
)

func main() {
	// Create a sample configuration.
	cfg := types.Config{
		MaxRequestsPerSecond: 5,
		BlockedIPs:           []string{"192.168.1.100"},
		CustomRules: []types.Rule{
			{
				ID:       "rule1",
				SourceIP: "",         // Empty means any source
				DestIP:   "10.0.0.1", // Block destination IP 10.0.0.1
				Protocol: "TCP",
				Port:     80,
			},
		},
	}

	// Instantiate the firewall.
	fw, err := api.NewFirewall(cfg)
	if err != nil {
		log.Fatalf("Error creating firewall: %v", err)
	}

	// Create a test request.
	testReq := types.Request{
		SourceIP: "192.168.1.200",
		DestIP:   "10.0.0.1",
		Protocol: "TCP",
		Port:     80,
	}

	// Process the test request using the Filter method.
	resp, err := fw.Filter(context.Background(), testReq)
	if err != nil {
		log.Fatalf("Filter error: %v", err)
	}

	// Pretty-print the response.
	respJSON, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Println("Filter response:")
	fmt.Println(string(respJSON))
}
