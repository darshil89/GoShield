package api

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/darshil89/firewall/types"
)

// FirewallImpl is a concrete implementation of the Firewall interface.
type FirewallImpl struct {
	mu          sync.RWMutex
	rules       map[string]types.Rule // Stores custom rules keyed by rule ID.
	blockedIPs  map[string]bool       // Quick lookup for blocked IP addresses.
	rateLimiter *RateLimiter          // Limits requests per second.
}

// NewFirewall creates a new firewall instance based on the provided configuration.
func NewFirewall(cfg types.Config) (types.Firewall, error) {
	f := &FirewallImpl{
		rules:       make(map[string]types.Rule),
		blockedIPs:  make(map[string]bool),
		rateLimiter: NewRateLimiter(cfg.MaxRequestsPerSecond),
	}

	// Set up blocked IPs.
	for _, ip := range cfg.BlockedIPs {
		f.blockedIPs[ip] = true
	}

	// Add any custom rules provided.
	for _, rule := range cfg.CustomRules {
		f.rules[rule.ID] = rule
	}

	return f, nil
}

// Filter evaluates an incoming request against the firewall rules.
func (f *FirewallImpl) Filter(ctx context.Context, req types.Request) (types.Response, error) {
	// Rate limiting check.
	if !f.rateLimiter.Allow() {
		return types.Response{Allowed: false, Message: "Rate limit exceeded"}, nil
	}

	f.mu.RLock()
	// Check if the request comes from a blocked IP.
	if f.blockedIPs[req.SourceIP] {
		f.mu.RUnlock()
		return types.Response{Allowed: false, Message: "Blocked IP"}, nil
	}

	// Evaluate custom rules.
	for _, rule := range f.rules {
		if rule.SourceIP == req.SourceIP &&
			rule.DestIP == req.DestIP &&
			rule.Protocol == req.Protocol &&
			rule.Port == req.Port {
			f.mu.RUnlock()
			return types.Response{Allowed: false, Message: "Blocked by custom rule"}, nil
		}
	}
	f.mu.RUnlock()

	return types.Response{Allowed: true, Message: "Request allowed"}, nil
}

// AddRule allows adding a new rule at runtime.
func (f *FirewallImpl) AddRule(rule types.Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.rules[rule.ID]; exists {
		return errors.New("rule already exists")
	}
	f.rules[rule.ID] = rule
	return nil
}

// RemoveRule allows removal of a rule by its ID.
func (f *FirewallImpl) RemoveRule(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.rules[id]; !exists {
		return errors.New("rule not found")
	}
	delete(f.rules, id)
	return nil
}

// RateLimiter is a simple implementation of rate limiting.
type RateLimiter struct {
	maxRequests int
	mu          sync.Mutex
	requests    int
	resetTime   time.Time
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(max int) *RateLimiter {
	return &RateLimiter{
		maxRequests: max,
		resetTime:   time.Now().Add(time.Second),
	}
}

// Allow checks whether a new request can be processed.
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	if now.After(rl.resetTime) {
		rl.requests = 0
		rl.resetTime = now.Add(time.Second)
	}
	if rl.requests < rl.maxRequests {
		rl.requests++
		return true
	}
	return false
}
