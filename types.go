package memoryscanner

import (
	"fmt"
	"strings"
)

// Address represents a memory address
type Address uint64

// String returns the hexadecimal representation of the address
func (a Address) String() string {
	return fmt.Sprintf("0x%X", uint64(a))
}

// Match represents a single memory match result
type Match struct {
	Address Address
	Data    []byte
}

// Content returns the data as a UTF-8 string, replacing invalid UTF-8 sequences
func (m Match) Content() string {
	return strings.ToValidUTF8(string(m.Data), "")
}

// MatchHandler is called for each memory match found during scanning.
// Return false to stop the scan, true to continue.
type MatchHandler func(match Match) bool

// ScanOptions contains configuration options for memory scanning
type ScanOptions struct {
	// Pattern to search for (AOB format)
	Pattern string
	// Whether to ignore case when searching text
	IgnoreCase bool
	// Minimum address to start scanning from (inclusive)
	MinAddress Address
	// Maximum address to scan to (inclusive)
	MaxAddress Address
	// Handler called for each match found
	Handler MatchHandler
}
