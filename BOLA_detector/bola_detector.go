package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// LogEntry represents the structure of each log entry in the access log.
type LogEntry struct {
	Req struct {
		URL        string `json:"url"`
		QSParams   string `json:"qs_params"`
		Headers    string `json:"Headers"`
		ReqBodyLen int    `json:"req_body_len"`
	} `json:"req"`
	Rsp struct {
		StatusClass string `json:"status_class"`
		RspBodyLen  int    `json:"rsp_body_len"`
	} `json:"rsp"`
}

// detectBOLA checks the specified log file for potential BOLA attacks by analyzing access patterns.
func detectBOLA(logFilename string) {
	file, err := os.Open(logFilename)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close() // Ensure the file is closed when the function exits

	scanner := bufio.NewScanner(file)
	accessPatterns := make(map[string]map[string]bool) // Map to track which user IDs accessed each URL

	for scanner.Scan() {
		var entry LogEntry
		line := scanner.Text()

		// Parse the JSON log entry into the LogEntry struct
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			fmt.Printf("Error decoding JSON: %v\n", err)
			continue
		}

		// Parse the query string (qs_params) into a map-like structure
		qsParams, err := url.ParseQuery(entry.Req.QSParams)
		if err != nil {
			fmt.Printf("Error parsing query string: %v\n", err)
			continue
		}

		userID := qsParams.Get("user_id") // Extract the user_id parameter
		if userID == "" {
			continue // Skip if user_id is not found
		}

		url := strings.Split(entry.Req.URL, "?")[0] // Extract the base URL (ignore query string)

		if _, exists := accessPatterns[url]; !exists {
			accessPatterns[url] = make(map[string]bool) // Initialize map for the URL
		}
		accessPatterns[url][userID] = true // Mark this user ID as having accessed the URL
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	// Check if multiple users accessed the same URL
	for url, users := range accessPatterns {
		if len(users) > 1 {
			fmt.Printf("Potential BOLA detected at %s: Accessed by user IDs %v\n", url, mapKeys(users))
		}
	}
}

// mapKeys extracts the keys from a map into a slice of strings.
func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: bola_detector <log_filename>")
		return
	}

	logFilename := os.Args[1]
	detectBOLA(logFilename)
}
