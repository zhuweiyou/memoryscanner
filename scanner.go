package memoryscanner

import (
	"context"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Scanner represents a memory scanner for a specific process
type Scanner struct {
	pid        uint32
	processHandle windows.Handle
}

// NewScanner creates a new memory scanner for the specified process ID
func NewScanner(pid uint32) (*Scanner, error) {
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open process: %w", err)
	}

	return &Scanner{
		pid:        pid,
		processHandle: hProcess,
	}, nil
}

// Close closes the process handle
func (s *Scanner) Close() error {
	if s.processHandle != 0 {
		windows.CloseHandle(s.processHandle)
		s.processHandle = 0
	}
	return nil
}

// GetPID returns the process ID that this scanner is attached to
func (s *Scanner) GetPID() uint32 {
	return s.pid
}

// Scan scans the process memory for the specified pattern
func (s *Scanner) Scan(ctx context.Context, opts ScanOptions) error {
	patternMatcher, err := NewPatternMatcher(opts.Pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}

	var mbi windows.MemoryBasicInformation
	address := uint64(opts.MinAddress)
	maxAddress := uint64(opts.MaxAddress)

	for address < maxAddress {
		// Check if context was cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err = windows.VirtualQueryEx(s.processHandle, uintptr(address), &mbi, unsafe.Sizeof(mbi))
		if err != nil {
			break
		}

		baseAddr := uint64(mbi.BaseAddress)
		regionSize := uint64(mbi.RegionSize)

		// Check if this memory region is readable
		if s.isReadableRegion(&mbi) {
			if err := s.scanRegion(ctx, baseAddr, regionSize, maxAddress, patternMatcher, opts); err != nil {
				return err
			}
		}

		// Move to next region
		address = baseAddr + regionSize
		if regionSize == 0 {
			address++
		}
	}

	return nil
}

// isReadableRegion checks if a memory region is readable
func (s *Scanner) isReadableRegion(mbi *windows.MemoryBasicInformation) bool {
	isReadable := mbi.Protect&(windows.PAGE_READONLY|windows.PAGE_READWRITE|
		windows.PAGE_EXECUTE_READ|windows.PAGE_EXECUTE_READWRITE) != 0
	isCommitted := mbi.State == windows.MEM_COMMIT

	return isReadable && isCommitted
}

// scanRegion scans a specific memory region for matches
func (s *Scanner) scanRegion(ctx context.Context, baseAddr, regionSize, maxAddress uint64,
	matcher *PatternMatcher, opts ScanOptions) error {

	// Calculate read bounds
	readEnd := baseAddr + regionSize
	if readEnd > maxAddress {
		readEnd = maxAddress
	}

	if readEnd <= baseAddr {
		return nil
	}

	readLength := readEnd - baseAddr
	buffer := make([]byte, readLength)
	var bytesRead uintptr

	// Read memory region
	err := windows.ReadProcessMemory(s.processHandle, uintptr(baseAddr), &buffer[0],
		uintptr(readLength), &bytesRead)
	if err != nil || bytesRead == 0 {
		return nil
	}

	// Trim buffer to actual bytes read
	buffer = buffer[:bytesRead]

	// Find matches in this region
	matches := matcher.FindMatches(buffer, opts.IgnoreCase)
	for _, offset := range matches {
		// Check if context was cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		absoluteAddress := Address(baseAddr + uint64(offset))

		// Extract matched data
		if offset+matcher.GetPatternLength() > len(buffer) {
			continue
		}

		matchedData := make([]byte, matcher.GetPatternLength())
		copy(matchedData, buffer[offset:offset+matcher.GetPatternLength()])

		match := Match{
			Address: absoluteAddress,
			Data:    matchedData,
		}

		// Call handler and stop if requested
		if !opts.Handler(match) {
			return nil
		}
	}

	return nil
}