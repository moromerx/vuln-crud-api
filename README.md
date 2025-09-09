# Vulnerability CRUD API

A simple CRUD API built with Golang to manage vulnerability records.
I created this project as a learning exercise to practice building RESTful APIs in Go and testing them with Postman.  

## Features

- **CRUD Operations**
  - **GET** all vulnerabilities or a single vulnerability by ID.
  - **POST** to create new vulnerabilities with validation (CVE is required).
  - **PUT** to update existing vulnerabilities.
  - **DELETE** to remove vulnerabilities.

- **Data Model**  
  Each vulnerability record stores:
  - `ID` (UUID)
  - `CVE` (CVE identifier, required)
  - `Severity` (Critical, High, Medium, Low)
  - `Description`
  - `Discovered` (timestamp)
  - `Status` (Open, Closed, In Progress)

- **Pre-added Data**  
  Two vulnerabilities are present when the server starts:
  - `CVE-2021-44228` (Log4Shell)
  - `CVE-2017-0144` (WannaCry Ransomware)

## Testing

### Unit Tests

I wrote two unit tests for the **GetAll** endpoint:

1. **Valid Path** – returns a populated list of vulnerabilities.  
2. **Empty List** – returns an empty list with a `200 OK` status.  

More tests (for 'GET by ID', 'POST', etc.) can be added.

### Postman Testing

I tested the API with Postman to validate endpoints under different conditions (valid requests, invalid UUIDs, missing fields, etc.).

See **[Postman-Testing.md](./Postman-Testing.md)** for screenshots of the results.
