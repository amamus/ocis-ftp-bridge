// Package http provides HTTP endpoints for ocis-ftp-bridge observability and operations.
//
// This package implements the HTTP endpoints required for health checks, readiness probes,
// and Prometheus metrics exposure as specified in Issue #9.
package http

import (
	"context"
	"fmt"
	"net"
	"net/http"
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

	// Metrics collectors (stored as interfaces for registration)
	ftpSessionsTotal       prometheus.Collector
	ftpActiveSessions      prometheus.Collector
	ftpUploadsTotal        prometheus.Collector
	ftpUploadFailuresTotal prometheus.Collector
	ftpUploadBytesTotal    prometheus.Collector
	ftpUploadDuration      prometheus.Collector
	ocisRequestsTotal      prometheus.Collector
}

// NewOperationsServer creates a new operations HTTP server
func NewOperationsServer(address string) *OperationsServer {
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

	// Register all metrics
	registry.MustRegister(
		ftpSessionsTotal,
		ftpActiveSessions,
		ftpUploadsTotal,
		ftpUploadFailuresTotal,
		ftpUploadBytesTotal,
		ftpUploadDuration,
		ocisRequestsTotal,
	)

	// Set up HTTP routes
	mux := http.NewServeMux()

	// Create the server struct first so we can reference it in handlers
	s := &OperationsServer{
		address:               address,
		mux:                  mux,
		healthy:               1,
		ready:                 1,
		ftpSessionsTotal:      ftpSessionsTotal,
		ftpActiveSessions:     ftpActiveSessions,
		ftpUploadsTotal:       ftpUploadsTotal,
		ftpUploadFailuresTotal: ftpUploadFailuresTotal,
		ftpUploadBytesTotal:   ftpUploadBytesTotal,
		ftpUploadDuration:     ftpUploadDuration,
		ocisRequestsTotal:     ocisRequestsTotal,
	}

	// Health endpoint
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&s.healthy) == 0 {
			http.Error(w, "Service is unhealthy", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Readiness endpoint
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&s.ready) == 0 {
			http.Error(w, "Service is not ready to accept traffic", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
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

	// Wait for server to start and capture the actual address
	time.Sleep(100 * time.Millisecond)

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