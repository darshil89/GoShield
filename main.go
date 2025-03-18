package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/darshil89/firewall/api"
	"github.com/darshil89/firewall/types"
)

func main() {
	// Create a sample configuration.
	cfg := types.Config{
		MaxRequestsPerSecond: 10,
		BlockedIPs:           []string{"192.168.1.100"},
		CustomRules: []types.Rule{
			{
				ID:       "rule1",
				SourceIP: "",         // Empty means any source
				DestIP:   "10.0.0.1", // Example destination IP to block
				Protocol: "TCP",
				Port:     80,
			},
		},
	}

	// Instantiate the firewall using the public API.
	fw, err := api.NewFirewall(cfg)
	if err != nil {
		log.Fatalf("Error creating firewall: %v", err)
	}

	// Create the chi router and apply middleware.
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	// Simple test endpoint.
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Testing server!!"))
	})

	// Endpoint to filter requests.
	// Clients can send a JSON payload matching types.Request.
	r.Post("/filter", func(w http.ResponseWriter, r *http.Request) {
		var req types.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		resp, err := fw.Filter(context.Background(), req)
		if err != nil {
			http.Error(w, "Error filtering request", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Endpoint to add a new rule.
	r.Post("/rules", func(w http.ResponseWriter, r *http.Request) {
		var rule types.Rule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "Invalid rule format", http.StatusBadRequest)
			return
		}

		if err := fw.AddRule(rule); err != nil {
			http.Error(w, "Error adding rule: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
	})

	// Endpoint to remove a rule by its ID.
	r.Delete("/rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if err := fw.RemoveRule(id); err != nil {
			http.Error(w, "Error removing rule: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	log.Println("Server listening on :3000")
	http.ListenAndServe(":3000", r)
}
