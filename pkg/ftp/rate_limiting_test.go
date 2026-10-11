package ftp

import (
	"testing"
	"time"
)

func TestConnectionTracker(t *testing.T) {
	t.Run("allow connections within limits", func(t *testing.T) {
		tracker := newConnectionTracker(10, 100)
		
		// Test connections from one IP
		ip := "192.168.1.1"
		for i := 0; i < 10; i++ {
			if !tracker.AllowConnection(ip) {
				t.Errorf("Expected connection %d from IP %s to be allowed", i+1, ip)
			}
		}
		
		// 11th connection should be rejected
		if tracker.AllowConnection(ip) {
			t.Error("Expected 11th connection from same IP to be rejected")
		}
	})
	
	t.Run("multiple IPs", func(t *testing.T) {
		tracker := newConnectionTracker(5, 100)
		
		ips := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}
		
		// Each IP should be able to have 5 connections
		for _, ip := range ips {
			for i := 0; i < 5; i++ {
				if !tracker.AllowConnection(ip) {
					t.Errorf("Expected connection %d from IP %s to be allowed", i+1, ip)
				}
			}
		}
		
		// 6th connection from first IP should be rejected
		if tracker.AllowConnection(ips[0]) {
			t.Error("Expected 6th connection from first IP to be rejected")
		}
	})
	
	t.Run("global connection limit", func(t *testing.T) {
		tracker := newConnectionTracker(50, 10) // Global limit lower than per-IP
		
		// Create connections from different IPs
		for i := 0; i < 10; i++ {
			ip := "192.168.1." + string(rune('1'+i))
			if !tracker.AllowConnection(ip) {
				t.Errorf("Expected connection %d to be allowed", i+1)
			}
		}
		
		// 11th connection should be rejected due to global limit
		if tracker.AllowConnection("192.168.2.1") {
			t.Error("Expected 11th connection to be rejected due to global limit")
		}
	})
	
	t.Run("connection release", func(t *testing.T) {
		tracker := newConnectionTracker(2, 10)
		
		ip := "192.168.1.1"
		
		// Use up the connections
		tracker.AllowConnection(ip)
		tracker.AllowConnection(ip)
		
		// Should be rejected now
		if tracker.AllowConnection(ip) {
			t.Error("Expected 3rd connection to be rejected")
		}
		
		// Release a connection
		tracker.ReleaseConnection(ip)
		
		// Should be allowed again
		if !tracker.AllowConnection(ip) {
			t.Error("Expected connection after release to be allowed")
		}
	})
	
	t.Run("nil tracker allows all", func(t *testing.T) {
		var tracker *ConnectionTracker // nil
		
		// All connections should be allowed when tracker is nil
		for i := 0; i < 100; i++ {
			if !tracker.AllowConnection("192.168.1.1") {
				t.Errorf("Expected connection %d to be allowed with nil tracker", i+1)
			}
		}
	})
}

// TestConnectionTrackerZeroLimits verifies that zero limits are treated as unlimited.
func TestConnectionTrackerZeroLimits(t *testing.T) {
	t.Run("zero global limit is unlimited", func(t *testing.T) {
		tracker := newConnectionTracker(10, 0) // 0 global = unlimited
		// Should allow many connections
		for i := 0; i < 200; i++ {
			ip := "192.168.1." + string(rune('1'+i%250))
			if !tracker.AllowConnection(ip) {
				t.Fatalf("Expected connection %d to be allowed with zero global limit", i+1)
			}
		}
	})

	t.Run("zero per-IP limit is unlimited", func(t *testing.T) {
		tracker := newConnectionTracker(0, 100) // 0 per-IP = unlimited
		ip := "192.168.1.1"
		// Should allow many connections from same IP
		for i := 0; i < 50; i++ {
			if !tracker.AllowConnection(ip) {
				t.Fatalf("Expected connection %d to be allowed with zero per-IP limit", i+1)
			}
		}
	})
}

// TestExtractClientIP verifies that the client IP is correctly extracted
// from a RemoteAddr that includes a port.
func TestExtractClientIP(t *testing.T) {
	testCases := []struct {
		name     string
		remoteAddr string
		expected string
	}{
		{"IPv4 with port", "192.168.1.1:12345", "192.168.1.1"},
		{"IPv4 with port 2", "10.0.0.1:54321", "10.0.0.1"},
		{"IPv6 with port", "[::1]:12345", "::1"},
		{"IPv6 with port 2", "[fe80::1]:8080", "fe80::1"},
		{"no port (fallback)", "192.168.1.1", "192.168.1.1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := extractClientIP(tc.remoteAddr)
			if result != tc.expected {
				t.Errorf("extractClientIP(%q) = %q, expected %q", tc.remoteAddr, result, tc.expected)
			}
		})
	}
}

func TestAuthAttemptTracker(t *testing.T) {
	t.Run("successful authentication resets tracking", func(t *testing.T) {
		tracker := newAuthAttemptTracker(3, time.Minute, 5*time.Minute)
		ip := "192.168.1.1"
		
		// Record 2 failed attempts (maxAttempts = 3, so 2 should be allowed)
		if !tracker.RecordAuthAttempt(ip, false) {
			t.Error("Expected failed attempt to be recorded")
		}
		if !tracker.RecordAuthAttempt(ip, false) {
			t.Error("Expected failed attempt to be recorded")
		}
		
		// 3rd failed attempt should trigger lockout (count >= maxAttempts)
		if tracker.RecordAuthAttempt(ip, false) {
			t.Error("Expected 3rd failed attempt to trigger lockout")
		}
		
		// Check if IP is locked out
		if !tracker.IsIPLockedOut(ip) {
			t.Error("Expected IP to be locked out after max failed attempts")
		}
	})
	
	t.Run("successful auth resets counter", func(t *testing.T) {
		tracker := newAuthAttemptTracker(3, time.Minute, 5*time.Minute)
		ip := "192.168.1.2"
		
		// Record 2 failed attempts
		tracker.RecordAuthAttempt(ip, false)
		tracker.RecordAuthAttempt(ip, false)
		
		// Successful authentication should reset the counter
		if !tracker.RecordAuthAttempt(ip, true) {
			t.Error("Expected successful auth to be recorded")
		}
		
		// Should be allowed to fail again after success
		if !tracker.RecordAuthAttempt(ip, false) {
			t.Error("Expected failed attempt after success to be allowed")
		}
	})
	
	t.Run("lockout expiration", func(t *testing.T) {
		tracker := newAuthAttemptTracker(2, 10*time.Millisecond, 20*time.Millisecond)
		ip := "192.168.1.3"
		
		// Exhaust the attempts to trigger lockout
		tracker.RecordAuthAttempt(ip, false)
		tracker.RecordAuthAttempt(ip, false)
		
		// Should be locked out
		if !tracker.IsIPLockedOut(ip) {
			t.Error("Expected IP to be locked out")
		}
		
		// Wait for lockout to expire
		time.Sleep(25 * time.Millisecond)
		
		// Should no longer be locked out
		if tracker.IsIPLockedOut(ip) {
			t.Error("Expected IP to no longer be locked out after expiration")
		}
	})
	
	t.Run("window expiration resets counter", func(t *testing.T) {
		// Use a short lockout duration to test window expiration behavior
		tracker := newAuthAttemptTracker(2, 10*time.Millisecond, 15*time.Millisecond)
		ip := "192.168.1.4"
		
		// Exhaust the attempts
		tracker.RecordAuthAttempt(ip, false)
		tracker.RecordAuthAttempt(ip, false)
		
		// Should be locked out
		if !tracker.IsIPLockedOut(ip) {
			t.Error("Expected IP to be locked out")
		}
		
		// Wait for both the window and lockout to expire
		time.Sleep(20 * time.Millisecond)
		
		// Should no longer be locked out and counter should be reset
		if tracker.IsIPLockedOut(ip) {
			t.Error("Expected IP to no longer be locked out after lockout expiration")
		}
		
		// Should be able to fail again
		if !tracker.RecordAuthAttempt(ip, false) {
			t.Error("Expected failed attempt after lockout expiration to be allowed")
		}
	})
	
	t.Run("nil tracker allows all", func(t *testing.T) {
		var tracker *AuthAttemptTracker // nil
		
		// All attempts should be allowed when tracker is nil
		for i := 0; i < 100; i++ {
			if !tracker.RecordAuthAttempt("192.168.1.1", false) {
				t.Errorf("Expected attempt %d to be allowed with nil tracker", i+1)
			}
		}
		
		if tracker.IsIPLockedOut("192.168.1.1") {
			t.Error("Expected IP to not be locked out with nil tracker")
		}
	})
}