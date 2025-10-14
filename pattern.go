package memoryscanner

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// StringToPattern converts a search string to an AOB (Array of Bytes) pattern.
// Wildcard characters (?) are converted to "??". The pattern is padded to the specified length.
func StringToPattern(searchStr string, minLength int) string {
	if searchStr == "" {
		return ""
	}

	var builder strings.Builder
	bytes := []byte(searchStr)
	patternLength := len(bytes)
	if minLength > patternLength {
		patternLength = minLength
	}

	for i := 0; i < patternLength; i++ {
		if i > 0 {
			builder.WriteString(" ")
		}

		if i < len(bytes) {
			b := bytes[i]
			if b == '?' {
				builder.WriteString("??")
			} else {
				builder.WriteString(fmt.Sprintf("%02X", b))
			}
		} else {
			builder.WriteString("??")
		}
	}

	return builder.String()
}

// PatternMatcher handles pattern matching logic
type PatternMatcher struct {
	patternBytes  []byte
	wildcardMask  []bool
	patternLength int
}

// NewPatternMatcher creates a new pattern matcher from an AOB pattern string
func NewPatternMatcher(pattern string) (*PatternMatcher, error) {
	parts := strings.Fields(pattern)
	if len(parts) == 0 {
		return nil, errors.New("empty pattern")
	}

	patternBytes := make([]byte, len(parts))
	wildcardMask := make([]bool, len(parts))

	for i, part := range parts {
		if part == "??" {
			wildcardMask[i] = true
		} else {
			decoded, err := hex.DecodeString(part)
			if err != nil || len(decoded) != 1 {
				return nil, fmt.Errorf("invalid hex pattern: %s", part)
			}
			patternBytes[i] = decoded[0]
		}
	}

	return &PatternMatcher{
		patternBytes:  patternBytes,
		wildcardMask:  wildcardMask,
		patternLength: len(parts),
	}, nil
}

// FindMatches finds all occurrences of the pattern in the given data
func (pm *PatternMatcher) FindMatches(data []byte, ignoreCase bool) []int {
	if pm.patternLength == 0 || pm.patternLength > len(data) {
		return nil
	}

	var matches []int
	dataLen := len(data)

	for i := 0; i <= dataLen-pm.patternLength; i++ {
		if pm.matchesAt(data, i, ignoreCase) {
			matches = append(matches, i)
		}
	}

	return matches
}

// matchesAt checks if the pattern matches at the given position
func (pm *PatternMatcher) matchesAt(data []byte, pos int, ignoreCase bool) bool {
	for j := 0; j < pm.patternLength; j++ {
		if pm.wildcardMask[j] {
			continue // Skip wildcards
		}

		dataByte := data[pos+j]
		patternByte := pm.patternBytes[j]

		if ignoreCase {
			// Convert both to uppercase for ASCII case-insensitive comparison
			if 'a' <= patternByte && patternByte <= 'z' {
				patternByte -= ('a' - 'A')
			}
			if 'a' <= dataByte && dataByte <= 'z' {
				dataByte -= ('a' - 'A')
			}
		}

		if dataByte != patternByte {
			return false
		}
	}

	return true
}

// GetPatternLength returns the length of the pattern in bytes
func (pm *PatternMatcher) GetPatternLength() int {
	return pm.patternLength
}