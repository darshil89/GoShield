package types

import "context"

type Firewall interface {
	Filter(ctx context.Context, request Request) (Response, error)
	AddRule(rule Rule) error
	RemoveRule(id string) error
}

type Request struct {
	SourceIP string
	DestIP   string
	Protocol string
	Port     int
}

type Rule struct {
	ID       string
	SourceIP string
	DestIP   string
	Protocol string
	Port     int
}

type Response struct {
	Allowed bool
	Message string
}

type Config struct {
	MaxRequestsPerSecond int
	BlockedIPs           []string
	CustomRules          []Rule
}
