package memoryscanner

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FindProcessesByName finds all processes with the specified name
func FindProcessesByName(name string) ([]uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create process snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	if err := windows.Process32First(snapshot, &pe32); err != nil {
		return nil, fmt.Errorf("failed to enumerate processes: %w", err)
	}

	var pids []uint32
	for {
		processName := windows.UTF16ToString(pe32.ExeFile[:])
		if strings.EqualFold(processName, name) {
			pids = append(pids, pe32.ProcessID)
		}

		if err := windows.Process32Next(snapshot, &pe32); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return nil, fmt.Errorf("failed to enumerate processes: %w", err)
		}
	}

	if len(pids) == 0 {
		return nil, fmt.Errorf("process not found: %s", name)
	}

	return pids, nil
}