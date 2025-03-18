package types

import "context"

// Firewall defines the interface for our firewall backend.
type Firewall interface {
	Filter(ctx context.Context, request Request) (Response, error)
	AddRule(rule Rule) error
	RemoveRule(id string) error
}

// Request represents an incoming request to be filtered.
type Request struct {
	SourceIP string
	DestIP   string
	Protocol string
	Port     int
}

// Rule represents a filtering rule.
type Rule struct {
	ID       string
	SourceIP string
	DestIP   string
	Protocol string
	Port     int
}

// Response represents the outcome of a filtering operation.
type Response struct {
	Allowed bool
	Message string
}

// Config holds configuration settings for the firewall.
type Config struct {
	MaxRequestsPerSecond int
	BlockedIPs           []string
	CustomRules          []Rule
}
