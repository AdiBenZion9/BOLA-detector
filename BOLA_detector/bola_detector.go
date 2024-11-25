package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// LogEntry represents the structure of each log entry in the access log.
type LogEntry struct {
	Req struct {
		URL      string            `json:"url"`
		QSParams map[string]string `json:"qs_params"`
	} `json:"req"`
}

// detectBOLA checks the specified log file for potential BOLA attacks by analyzing access patterns.
func detectBOLA(logFilename string) {
	file, err := os.Open(logFilename)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	accessPatterns := make(map[string]map[string]bool)

	for scanner.Scan() {
		var entry LogEntry
		line := scanner.Text()

		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			fmt.Printf("Error decoding JSON: %v\n", err)
			continue
		}

		userID, ok := entry.Req.QSParams["user_id"]
		if !ok {
			continue // skip if no user_id is present
		}

		url := strings.Split(entry.Req.URL, "?")[0]

		if _, exists := accessPatterns[url]; !exists {
			accessPatterns[url] = make(map[string]bool)
		}
		accessPatterns[url][userID] = true
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

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
