// Package http provides HTTP endpoints for ocis-ftp-bridge observability and operations.
//
// This package implements the HTTP endpoints required for health checks, readiness probes,
// and Prometheus metrics exposure as specified in Issue #9.
package http

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server provides HTTP operations endpoints
type Server interface {
	// Run starts the HTTP server
	Run(ctx context.Context) error
	// Stop shuts down the HTTP server
	Stop() error
}

// OperationsServer implements the HTTP operations server
type OperationsServer struct {
	server     *http.Server
	wg         sync.WaitGroup
	started    bool
	mu         sync.Mutex
	actualAddr string
	mux        *http.ServeMux
	address    string

	// Health and readiness state
	healthy int32 // atomic: 1 = healthy, 0 = unhealthy
	ready   int32 // atomic: 1 = ready, 0 = not ready

	// Configuration for health checks
	ocisURL              string
	ocisUsername         string
	ocisPassword         string
	webdavURL            string
	spoolDirectory       string
	checkTimeout         time.Duration
	
	// HTTP client for connectivity checks
	httpClient *http.Client

	// Metrics collectors (stored as interfaces for registration)
	ftpSessionsTotal       prometheus.Collector
	ftpActiveSessions      prometheus.Collector
	ftpUploadsTotal        prometheus.Collector
	ftpUploadFailuresTotal prometheus.Collector
	ftpUploadBytesTotal    prometheus.Collector
	ftpUploadDuration      prometheus.Collector
	ocisRequestsTotal      prometheus.Collector
	
	// Health check metrics
	healthCheckTotal    prometheus.Collector
	healthCheckDuration prometheus.Collector
}

// HealthCheckConfig contains configuration for health checks
type HealthCheckConfig struct {
	OCISURL        string
	OCISUsername   string
	OCISPassword   string
	WebDAVURL      string
	SpoolDirectory string
	CheckTimeout   time.Duration
}

// NewOperationsServer creates a new operations HTTP server
// checkOCISConnectivity checks if the oCIS server is reachable
func (s *OperationsServer) checkOCISConnectivity() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.checkTimeout)
	defer cancel()
	
	url := s.ocisURL
	if !strings.HasSuffix(url, "/") {
		url += "/"
	}
	url += "status"
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create oCIS request: %w", err)
	}
	
	// Add basic auth if credentials are configured
	if s.ocisUsername != "" && s.ocisPassword != "" {
		req.SetBasicAuth(s.ocisUsername, s.ocisPassword)
	}
	
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to oCIS: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oCIS returned non-OK status: %s", resp.Status)
	}
	
	return nil
}

// checkWebDAVConnectivity checks if the WebDAV endpoint is reachable
func (s *OperationsServer) checkWebDAVConnectivity() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.checkTimeout)
	defer cancel()
	
	url := s.webdavURL
	if !strings.HasSuffix(url, "/") {
		url += "/"
	}
	
	req, err := http.NewRequestWithContext(ctx, "PROPFIND", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create WebDAV request: %w", err)
	}
	
	// Add basic auth if credentials are configured
	if s.ocisUsername != "" && s.ocisPassword != "" {
		req.SetBasicAuth(s.ocisUsername, s.ocisPassword)
	}
	
	// Set required headers for WebDAV
	req.Header.Set("Depth", "0")
	req.Header.Set("Content-Type", "application/xml")
	
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to WebDAV: %w", err)
	}
	defer resp.Body.Close()
	
	// WebDAV may return 401 (Unauthorized) which is still a successful connection
	// We want to check if we can reach the server, not necessarily if we're authenticated
	if resp.StatusCode != http.StatusOK && 
	   resp.StatusCode != http.StatusUnauthorized && 
	   resp.StatusCode != http.StatusForbidden {
		return fmt.Errorf("WebDAV returned unexpected status: %s", resp.Status)
	}
	
	return nil
}

// checkSpoolDirectory checks if the spool directory exists and is writable
func (s *OperationsServer) checkSpoolDirectory() error {
	if s.spoolDirectory == "" {
		return errors.New("spool directory not configured")
	}
	
	// Check if directory exists
	info, err := os.Stat(s.spoolDirectory)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("spool directory %q does not exist", s.spoolDirectory)
		}
		return fmt.Errorf("cannot access spool directory %q: %w", s.spoolDirectory, err)
	}
	
	if !info.IsDir() {
		return fmt.Errorf("spool path %q is not a directory", s.spoolDirectory)
	}
	
	// Check if directory is writable
	// Try to create a test file and remove it
	testFile := filepath.Join(s.spoolDirectory, ".healthcheck_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("spool directory %q is not writable: %w", s.spoolDirectory, err)
	}
	
	// Clean up the test file
	if err := os.Remove(testFile); err != nil && !os.IsNotExist(err) {
		// Log but don't fail the health check for cleanup failure
		fmt.Printf("Warning: failed to clean up health check test file: %v\n", err)
	}
	
	return nil
}

// performHealthChecks performs all health checks and returns the results
func (s *OperationsServer) performHealthChecks() (map[string]string, []string) {
	checks := make(map[string]string)
	var failedChecks []string
	
	// Check oCIS connectivity
	start := time.Now()
	if err := s.checkOCISConnectivity(); err != nil {
		checks["ocis_connectivity"] = "failed"
		failedChecks = append(failedChecks, fmt.Sprintf("oCIS connectivity: %s", err.Error()))
		
		// Record metrics
		if cv, ok := s.healthCheckTotal.(*prometheus.CounterVec); ok {
			cv.WithLabelValues("ocis_connectivity", "failed").Inc()
		}
	} else {
		checks["ocis_connectivity"] = "ok"
		
		// Record metrics
		if cv, ok := s.healthCheckTotal.(*prometheus.CounterVec); ok {
			cv.WithLabelValues("ocis_connectivity", "success").Inc()
		}
	}
	if hv, ok := s.healthCheckDuration.(*prometheus.HistogramVec); ok {
		hv.WithLabelValues("ocis_connectivity").Observe(time.Since(start).Seconds())
	}
	
	// Check WebDAV connectivity
	start = time.Now()
	if err := s.checkWebDAVConnectivity(); err != nil {
		checks["webdav_connectivity"] = "failed"
		failedChecks = append(failedChecks, fmt.Sprintf("WebDAV connectivity: %s", err.Error()))
		
		// Record metrics
		if cv, ok := s.healthCheckTotal.(*prometheus.CounterVec); ok {
			cv.WithLabelValues("webdav_connectivity", "failed").Inc()
		}
	} else {
		checks["webdav_connectivity"] = "ok"
		
		// Record metrics
		if cv, ok := s.healthCheckTotal.(*prometheus.CounterVec); ok {
			cv.WithLabelValues("webdav_connectivity", "success").Inc()
		}
	}
	if hv, ok := s.healthCheckDuration.(*prometheus.HistogramVec); ok {
		hv.WithLabelValues("webdav_connectivity").Observe(time.Since(start).Seconds())
	}
	
	// Check spool directory
	start = time.Now()
	if err := s.checkSpoolDirectory(); err != nil {
		checks["spool_directory"] = "failed"
		failedChecks = append(failedChecks, fmt.Sprintf("spool directory: %s", err.Error()))
		
		// Record metrics
		if cv, ok := s.healthCheckTotal.(*prometheus.CounterVec); ok {
			cv.WithLabelValues("spool_directory", "failed").Inc()
		}
	} else {
		checks["spool_directory"] = "ok"
		
		// Record metrics
		if cv, ok := s.healthCheckTotal.(*prometheus.CounterVec); ok {
			cv.WithLabelValues("spool_directory", "success").Inc()
		}
	}
	if hv, ok := s.healthCheckDuration.(*prometheus.HistogramVec); ok {
		hv.WithLabelValues("spool_directory").Observe(time.Since(start).Seconds())
	}
	
	return checks, failedChecks
}

func NewOperationsServer(address string, healthConfig HealthCheckConfig) *OperationsServer {
	// Create custom registry for our metrics
	registry := prometheus.NewRegistry()

	// Register standard Go metrics
	registry.MustRegister(prometheus.NewGoCollector())
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	// Create metrics
	ftpSessionsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ocis_ftp",
			Subsystem: "sessions",
			Name:      "total",
			Help:      "Total number of FTP sessions started",
		},
		[]string{"status"},
	)

	ftpActiveSessions := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ocis_ftp",
			Subsystem: "sessions",
			Name:      "active",
			Help:      "Number of currently active FTP sessions",
		},
	)

	ftpUploadsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ocis_ftp",
			Subsystem: "uploads",
			Name:      "total",
			Help:      "Total number of uploads processed",
		},
		[]string{"status"},
	)

	ftpUploadFailuresTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ocis_ftp",
			Subsystem: "uploads",
			Name:      "failures_total",
			Help:      "Total number of upload failures",
		},
		[]string{"reason"},
	)

	ftpUploadBytesTotal := prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "ocis_ftp",
			Subsystem: "uploads",
			Name:      "bytes_total",
			Help:      "Total number of bytes uploaded",
		},
	)

	ftpUploadDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "ocis_ftp",
			Subsystem: "uploads",
			Name:      "duration_seconds",
			Help:      "Upload duration in seconds",
			Buckets:   []float64{0.1, 0.5, 1, 5, 10, 30, 60, 120},
		},
		[]string{"status"},
	)

	ocisRequestsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ocis_ftp",
			Subsystem: "ocis",
			Name:      "requests_total",
			Help:      "Total number of requests made to oCIS",
		},
		[]string{"service", "status"},
	)

	// Create health check metrics
	healthCheckTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ocis_ftp",
			Subsystem: "health",
			Name:      "check_total",
			Help:      "Total number of health checks performed",
		},
		[]string{"check", "status"},
	)

	healthCheckDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "ocis_ftp",
			Subsystem: "health",
			Name:      "check_duration_seconds",
			Help:      "Duration of health checks in seconds",
			Buckets:   []float64{0.01, 0.05, 0.1, 0.5, 1, 2, 5},
		},
		[]string{"check"},
	)

	// Register all metrics
	registry.MustRegister(
		ftpSessionsTotal,
		ftpActiveSessions,
		ftpUploadsTotal,
		ftpUploadFailuresTotal,
		ftpUploadBytesTotal,
		ftpUploadDuration,
		ocisRequestsTotal,
		healthCheckTotal,
		healthCheckDuration,
	)

	// Create HTTP client for health checks
	healthCheckHTTPClient := &http.Client{
		Timeout: healthConfig.CheckTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        5,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	// Set up HTTP routes
	mux := http.NewServeMux()

	// Create the server struct first so we can reference it in handlers
	s := &OperationsServer{
		address:               address,
		mux:                  mux,
		healthy:               1,
		ready:                 1, // Start as ready, can be updated by health checks
		ocisURL:               healthConfig.OCISURL,
		ocisUsername:          healthConfig.OCISUsername,
		ocisPassword:          healthConfig.OCISPassword,
		webdavURL:             healthConfig.WebDAVURL,
		spoolDirectory:        healthConfig.SpoolDirectory,
		checkTimeout:          healthConfig.CheckTimeout,
		httpClient:            healthCheckHTTPClient,
		ftpSessionsTotal:      ftpSessionsTotal,
		ftpActiveSessions:     ftpActiveSessions,
		ftpUploadsTotal:       ftpUploadsTotal,
		ftpUploadFailuresTotal: ftpUploadFailuresTotal,
		ftpUploadBytesTotal:   ftpUploadBytesTotal,
		ftpUploadDuration:     ftpUploadDuration,
		ocisRequestsTotal:     ocisRequestsTotal,
		healthCheckTotal:      healthCheckTotal,
		healthCheckDuration:   healthCheckDuration,
	}

	// Health endpoint (liveness)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&s.healthy) == 0 {
			http.Error(w, "Service is unhealthy", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"live","timestamp":` + getCurrentTimestamp() + `}`))
	})

	// Readiness endpoint
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// Perform actual health checks
		checks, failedChecks := s.performHealthChecks()
		
		if len(failedChecks) > 0 {
			atomic.StoreInt32(&s.ready, 0)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			
			// Build error response
			errorsJSON := "["
			firstError := true
			for _, err := range failedChecks {
				if !firstError {
					errorsJSON += ","
				}
				firstError = false
				errorsJSON += `"` + escapeJSON(err) + `"`
			}
			errorsJSON += "]"
			
			checksJSON := "{"
			firstCheck := true
			for check, status := range checks {
				if !firstCheck {
					checksJSON += ","
				}
				firstCheck = false
				checksJSON += `"` + check + `":"` + status + `"`
			}
			checksJSON += "}"
			
			response := fmt.Sprintf(`{"status":"not_ready","checks":%s,"errors":%s,"timestamp":%s}`, 
				checksJSON, errorsJSON, getCurrentTimestamp())
			w.Write([]byte(response))
			return
		}
		
		// All checks passed
		atomic.StoreInt32(&s.ready, 1)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		
		checksJSON := "{"
		first := true
		for check, status := range checks {
			if !first {
				checksJSON += ","
			}
			first = false
			checksJSON += `"` + check + `":"` + status + `"`
		}
		checksJSON += "}"
		
		response := fmt.Sprintf(`{"status":"ready","checks":%s,"timestamp":%s}`, checksJSON, getCurrentTimestamp())
		w.Write([]byte(response))
	})

	// Metrics endpoint
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))

	s.server = &http.Server{
		Addr:    address,
		Handler: mux,
	}

	return s
}

// UpdateReadiness performs health checks and updates the readiness state accordingly
func (s *OperationsServer) UpdateReadiness() {
	_, failedChecks := s.performHealthChecks()
	
	if len(failedChecks) > 0 {
		atomic.StoreInt32(&s.ready, 0)
		fmt.Printf("Health checks failed: %v\n", failedChecks)
	} else {
		atomic.StoreInt32(&s.ready, 1)
	}
}

// getCurrentTimestamp returns the current timestamp in RFC3339 format
func getCurrentTimestamp() string {
	return time.Now().UTC().Format(`"` + time.RFC3339 + `"`)
}

// escapeJSON escapes special characters for JSON strings
func escapeJSON(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(
		strings.ReplaceAll(s, `\`, `\\`),
		`"`, `\"`),
		`\n`, `\n`),
		`\t`, `\t`)
}

// Run starts the HTTP server
func (s *OperationsServer) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("HTTP server already started")
	}
	s.started = true
	s.mu.Unlock()

	// Start the server and capture the actual listening address
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		
		// Start the server
		ln, err := net.Listen("tcp", s.address)
		if err != nil {
			return
		}
		
		// Store the actual address
		s.mu.Lock()
		s.actualAddr = ln.Addr().String()
		s.mu.Unlock()
		
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			return
		}
	}()

	// Start health check loop in the background (this will be managed by the server lifecycle)
	// Note: Health checks are performed on-demand in the /readyz endpoint

	return nil
}

// Stop shuts down the HTTP server
func (s *OperationsServer) Stop() error {
	s.mu.Lock()
	started := s.started
	s.mu.Unlock()

	if !started {
		return nil
	}

	// Shutdown the HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("HTTP server shutdown failed: %w", err)
	}

	// Wait for the server to stop
	s.wg.Wait()

	s.mu.Lock()
	s.started = false
	s.mu.Unlock()

	return nil
}

// SetHealthy sets the health status
func (s *OperationsServer) SetHealthy(healthy bool) {
	var val int32
	if healthy {
		val = 1
	}
	atomic.StoreInt32(&s.healthy, val)
}

// SetReady sets the readiness status
func (s *OperationsServer) SetReady(ready bool) {
	var val int32
	if ready {
		val = 1
	}
	atomic.StoreInt32(&s.ready, val)
}

// IsHealthy returns the current health status
func (s *OperationsServer) IsHealthy() bool {
	return atomic.LoadInt32(&s.healthy) == 1
}

// IsReady returns the current readiness status
func (s *OperationsServer) IsReady() bool {
	return atomic.LoadInt32(&s.ready) == 1
}

// Addr returns the actual address the server is listening on
func (s *OperationsServer) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.actualAddr
}

// Helper methods to access the metrics (type assertions are safe because we created them)

// IncrementFTPSessionTotal increments the total FTP sessions counter
func (s *OperationsServer) IncrementFTPSessionTotal(status string) {
	if cv, ok := s.ftpSessionsTotal.(*prometheus.CounterVec); ok {
		cv.WithLabelValues(status).Inc()
	}
}

// SetFTPActiveSessions sets the current number of active FTP sessions
func (s *OperationsServer) SetFTPActiveSessions(count float64) {
	if g, ok := s.ftpActiveSessions.(prometheus.Gauge); ok {
		g.Set(count)
	}
}

// IncrementUploadsTotal increments the upload counter
func (s *OperationsServer) IncrementUploadsTotal(status string) {
	if cv, ok := s.ftpUploadsTotal.(*prometheus.CounterVec); ok {
		cv.WithLabelValues(status).Inc()
	}
}

// IncrementUploadFailuresTotal increments the upload failure counter
func (s *OperationsServer) IncrementUploadFailuresTotal(reason string) {
	if cv, ok := s.ftpUploadFailuresTotal.(*prometheus.CounterVec); ok {
		cv.WithLabelValues(reason).Inc()
	}
}

// AddUploadBytes adds to the total upload bytes counter
func (s *OperationsServer) AddUploadBytes(bytes uint64) {
	if c, ok := s.ftpUploadBytesTotal.(prometheus.Counter); ok {
		c.Add(float64(bytes))
	}
}

// ObserveUploadDuration records an upload duration
func (s *OperationsServer) ObserveUploadDuration(duration time.Duration, status string) {
	if hv, ok := s.ftpUploadDuration.(*prometheus.HistogramVec); ok {
		hv.WithLabelValues(status).Observe(duration.Seconds())
	}
}

// IncrementOcisRequestsTotal increments the oCIS requests counter
func (s *OperationsServer) IncrementOcisRequestsTotal(service, status string) {
	if cv, ok := s.ocisRequestsTotal.(*prometheus.CounterVec); ok {
		cv.WithLabelValues(service, status).Inc()
	}
}