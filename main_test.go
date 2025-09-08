package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

func TestGetVulnerabilities_ValidPath(t *testing.T) {

	oldVulnerabilities := vulnerabilities

	// Cleaning up so every test starts fresh
	t.Cleanup(func() {
		vulnerabilities = oldVulnerabilities
	})

	vulnerabilities = []Vulnerability{
		{
			ID:          uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			CVE:         "CVE-2017-0144",
			Severity:    "Critical",
			Description: "Microsoft SMBv1 vulnerability exploited by WannaCry ransomware to execute arbitrary code remotely.",
			Discovered:  time.Date(2017, 3, 14, 0, 0, 0, 0, time.UTC),
			Status:      "Open",
		},
	}

	router := mux.NewRouter()
	router.HandleFunc("/vulnerabilities", getVulnerabilities).Methods("GET")

	req := httptest.NewRequest(http.MethodGet, "/vulnerabilities", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Assert

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}

	var response []Vulnerability

	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}

	if len(response) != 1 {
		t.Errorf("unexpected body: %+v", response)
	}

}

func TestGetVulnerabilities_EmptyList(t *testing.T) {

	oldVulnerabilities := vulnerabilities

	t.Cleanup(func() {
		vulnerabilities = oldVulnerabilities
	})

	vulnerabilities = []Vulnerability{}

	router := mux.NewRouter()
	router.HandleFunc("/vulnerabilities", getVulnerabilities).Methods("GET")

	req := httptest.NewRequest(http.MethodGet, "/vulnerabilities", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Assert

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}

	var response []Vulnerability

	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}

	if len(response) != 0 {
		t.Errorf("unexpected body: %+v", response)
	}
}
