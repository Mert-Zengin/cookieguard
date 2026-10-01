package threat

// Family is a documented infostealer and the cookie/browser-data techniques
// publicly reported against it. This is reference context for reviewers.
type Family struct {
	Name      string   `json:"name"`
	Aliases   []string `json:"aliases,omitempty"`
	Platforms []string `json:"platforms,omitempty"`
	Signals   []string `json:"signals"`
	Notes     string   `json:"notes"`
	Source    string   `json:"source"`
}

// familyOrder keeps output stable for tests and logs.
var familyOrder = []string{
	"Lumma Stealer", "RedLine Stealer", "Vidar", "Raccoon Stealer",
	"Agent Tesla", "Rhadamanthys", "Gremlin", "DarkCloud", "VoidStealer",
	"Epsilon Stealer", "Rakhni",
}

// familiesForSignal maps a defensive signal to families whose public reporting
// describes that technique. Presence is shared technique, not attribution.
var familiesForSignal = map[string][]string{
	"untrusted_cookie_access": {
		"Lumma Stealer", "RedLine Stealer", "Vidar", "Raccoon Stealer",
		"Agent Tesla", "Rhadamanthys", "Gremlin", "DarkCloud", "Epsilon Stealer",
	},
	"unsigned_binary": {
		"RedLine Stealer", "Vidar", "Agent Tesla", "Rhadamanthys", "DarkCloud",
		"Gremlin", "Raccoon Stealer", "Epsilon Stealer",
	},
	"user_writable_binary": {
		"RedLine Stealer", "Vidar", "Agent Tesla", "Rhadamanthys", "DarkCloud",
		"Gremlin", "Raccoon Stealer", "Epsilon Stealer", "Lumma Stealer",
	},
	"remote_debugging_switch": {
		"VoidStealer", "Lumma Stealer", "Raccoon Stealer", "RedLine Stealer", "Epsilon Stealer",
	},
	"profile_argument": {
		"VoidStealer", "Lumma Stealer", "Raccoon Stealer",
	},
	"browser_launched_by_untrusted_parent": {
		"Epsilon Stealer", "Lumma Stealer", "Raccoon Stealer",
	},
}

// Catalog returns the documented families. Callers must treat this as context,
// not as a detection result.
func Catalog() []Family {
	return []Family{
		{
			Name: "Lumma Stealer", Aliases: []string{"LummaC2"}, Platforms: []string{"windows"},
			Signals: []string{"untrusted_cookie_access", "user_writable_binary", "remote_debugging_switch", "profile_argument", "browser_launched_by_untrusted_parent"},
			Notes:   "Targets Chromium and Firefox browser stores; public reporting covers remote-debugging and profile abuse.",
			Source:  "https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/",
		},
		{
			Name: "RedLine Stealer", Platforms: []string{"windows"},
			Signals: []string{"untrusted_cookie_access", "unsigned_binary", "user_writable_binary", "remote_debugging_switch"},
			Notes:   ".NET stealer harvesting browser credentials, cookies, and wallets.",
			Source:  "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/RedLineStealer!rfn&ThreatID=2147817010",
		},
		{
			Name: "Vidar", Aliases: []string{"Vidar Stealer 2.0"}, Platforms: []string{"windows"},
			Signals: []string{"untrusted_cookie_access", "unsigned_binary", "user_writable_binary"},
			Notes:   "Documented browser-data theft and Chrome App-Bound Encryption bypass research; code-signing abuse reported.",
			Source:  "https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/",
		},
		{
			Name: "Raccoon Stealer", Aliases: []string{"Raccoon v2"}, Platforms: []string{"windows"},
			Signals: []string{"untrusted_cookie_access", "unsigned_binary", "user_writable_binary", "remote_debugging_switch", "profile_argument", "browser_launched_by_untrusted_parent"},
			Notes:   "Malware-as-a-service infostealer with broad browser coverage.",
			Source:  "https://attack.mitre.org/software/S1148/",
		},
		{
			Name: "Agent Tesla", Platforms: []string{"windows"},
			Signals: []string{"untrusted_cookie_access", "unsigned_binary", "user_writable_binary"},
			Notes:   ".NET RAT/stealer; public analysis covers multi-stage loaders and process hollowing.",
			Source:  "https://www.fortinet.com/blog/threat-research/unmasking-agent-tesla-deep-dive-into-multi-stage-campaign",
		},
		{
			Name: "Rhadamanthys", Platforms: []string{"windows"},
			Signals: []string{"untrusted_cookie_access", "unsigned_binary", "user_writable_binary"},
			Notes:   "Evolving stealer with browser session theft and evasion research.",
			Source:  "https://blog.checkpoint.com/research/rhadamanthys-0-9-2-a-stealer-that-keeps-evolving/",
		},
		{
			Name: "Gremlin", Platforms: []string{"windows"},
			Signals: []string{"untrusted_cookie_access", "unsigned_binary", "user_writable_binary"},
			Notes:   "Modular stealer using resource files and session hijacking techniques.",
			Source:  "https://unit42.paloaltonetworks.com/gremlin-stealer-evolution/",
		},
		{
			Name: "DarkCloud", Platforms: []string{"windows"},
			Signals: []string{"untrusted_cookie_access", "unsigned_binary", "user_writable_binary"},
			Notes:   "Stealer delivered via obfuscated AutoIt and script chains.",
			Source:  "https://unit42.paloaltonetworks.com/darkcloud-stealer-and-obfuscated-autoit-scripting/",
		},
		{
			Name: "VoidStealer", Platforms: []string{"windows"},
			Signals: []string{"remote_debugging_switch", "profile_argument", "untrusted_cookie_access"},
			Notes:   "Debugger-based Chrome App-Bound Encryption bypass research; targets live browser data.",
			Source:  "https://www.gendigital.com/blog/insights/research/voidstealer-abe-bypass",
		},
		{
			Name: "Epsilon Stealer", Platforms: []string{"windows"},
			Signals: []string{"untrusted_cookie_access", "unsigned_binary", "user_writable_binary", "remote_debugging_switch", "browser_launched_by_untrusted_parent"},
			Notes:   "NSIS-delivered Electron-era stealer reported to exfiltrate browser cookies and credentials.",
			Source:  "https://malpedia.caad.fkie.fraunhofer.de/details/win.epsilon_stealer",
		},
		{
			Name: "Rakhni", Platforms: []string{"windows"},
			Signals: []string{"untrusted_cookie_access", "unsigned_binary"},
			Notes:   "Loader/stealer family historically associated with browser credential theft.",
			Source:  "https://attack.mitre.org/techniques/T1555/003/",
		},
	}
}

// TechniqueSource documents the general technique references.
var TechniqueSources = []string{
	"https://attack.mitre.org/techniques/T1555/003/",
	"https://attack.mitre.org/techniques/T1055/",
	"https://www.elastic.co/guide/en/security/8.19/potential-cookies-theft-via-browser-debugging.html",
	"https://redcanary.com/blog/threat-intelligence/google-chrome-app-bound-encryption/",
}
