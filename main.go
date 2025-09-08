package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type Vulnerability struct {
	ID          uuid.UUID `json:"id"`
	CVE         string    `json:"cve"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Discovered  time.Time `json:"discovered"`
	Status      string    `json:"status"`
}

var vulnerabilities []Vulnerability

func getVulnerabilities(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vulnerabilities)
}

func getVulnerability(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	params := mux.Vars(r)
	ID, err := uuid.Parse(params["id"])
	if err != nil {
		http.Error(w, "id must be a valid UUID", http.StatusBadRequest)
		return
	}
	for _, item := range vulnerabilities {
		if item.ID == ID {
			json.NewEncoder(w).Encode(item)
			return
		}
	}
	http.Error(w, "id not found", http.StatusNotFound)
}

func createVulnerability(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	var vulnerability Vulnerability
	if err := json.NewDecoder(r.Body).Decode(&vulnerability); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if vulnerability.CVE == "" {
		http.Error(w, "CVE is required", http.StatusBadRequest)
		return
	}

	vulnerability.ID = uuid.New()
	vulnerabilities = append(vulnerabilities, vulnerability)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(vulnerability)
}

func updateVulnerability(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	params := mux.Vars(r)
	ID, err := uuid.Parse(params["id"])
	if err != nil {
		http.Error(w, "id must be a valid UUID", http.StatusBadRequest)
		return
	}

	for index, item := range vulnerabilities {
		if item.ID == ID {
			vulnerabilities = append(vulnerabilities[:index], vulnerabilities[index+1:]...)

			var vulnerability Vulnerability

			if err := json.NewDecoder(r.Body).Decode(&vulnerability); err != nil {
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
				return
			}

			vulnerability.ID = ID
			vulnerabilities = append(vulnerabilities, vulnerability)
			json.NewEncoder(w).Encode(vulnerability)
			return
		}
	}
}

func deleteVulnerability(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	params := mux.Vars(r)
	ID, err := uuid.Parse(params["id"])
	if err != nil {
		http.Error(w, "id must be a valid UUID", http.StatusBadRequest)
		return
	}

	for index, item := range vulnerabilities {
		if item.ID == ID {
			vulnerabilities = append(vulnerabilities[:index], vulnerabilities[index+1:]...)
		}
	}
}

func main() {

	r := mux.NewRouter()

	vulnerabilities = append(vulnerabilities,
		Vulnerability{
			ID:          uuid.New(),
			CVE:         "CVE-2021-44228",
			Severity:    "Critical",
			Description: "Apache Log4j2 Remote Code Execution (Log4Shell). Allows attackers to execute arbitrary code via crafted log messages.",
			Discovered:  time.Now(),
			Status:      "Open",
		},
		Vulnerability{
			ID:          uuid.New(),
			CVE:         "CVE-2017-0144",
			Severity:    "Critical",
			Description: "Microsoft SMBv1 vulnerability exploited by WannaCry ransomware to execute arbitrary code remotely.",
			Discovered:  time.Now(),
			Status:      "Open",
		},
	)

	r.HandleFunc("/vulnerabilities", getVulnerabilities).Methods("GET")
	r.HandleFunc("/vulnerabilities/{id}", getVulnerability).Methods("GET")
	r.HandleFunc("/vulnerabilities", createVulnerability).Methods("POST")
	r.HandleFunc("/vulnerabilities/{id}", updateVulnerability).Methods("PUT")
	r.HandleFunc("/vulnerabilities/{id}", deleteVulnerability).Methods("DELETE")

	fmt.Printf("Starting the server at port 8000\n")

	log.Fatal(http.ListenAndServe(":8000", r))

}