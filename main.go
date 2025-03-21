package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/darshil89/firewall/api"
	"github.com/darshil89/firewall/types"
)

var fw types.Firewall

func main() {
	// Create a sample configuration
	cfg := types.Config{
		MaxRequestsPerSecond: 2,
		BlockedIPs:           []string{"192.168.1.100"},
		CustomRules: []types.Rule{
			{
				ID:       "rule1",
				SourceIP: "",
				DestIP:   "10.0.0.1",
				Protocol: "TCP",
				Port:     80,
			},
		},
	}

	// Create firewall instance
	var err error
	fw, err = api.NewFirewall(cfg)
	if err != nil {
		log.Fatalf("Error creating firewall: %v", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Create a request object for the firewall
		req := types.Request{
			SourceIP: r.RemoteAddr,
			DestIP:   r.Host,
			Protocol: "HTTP",
			Port:     80,
		}

		// Use the firewall to filter the request
		ctx := context.Background()
		resp, err := fw.Filter(ctx, req)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if !resp.Allowed {
			http.Error(w, resp.Message, http.StatusForbidden)
			return
		}

		fmt.Fprintln(w, "Welcome to the firewall backend server")
	})

	// Start the server
	fmt.Println("Starting firewall backend server on :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
