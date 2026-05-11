// =============================================================================
// Mafsal — Zero Trust Browser Profile — prefs.js  (v4.0.0)
// Relay-integrated | Kill-Switch | Full anti-leak package
// Target: Firefox ESR 115+  |  Distribution: USB / Network Share — Zero Install
// =============================================================================

// --- [1] RAM-ONLY PROFILE (never write to disk) ---
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.disk.capacity", 0);
user_pref("browser.cache.disk.smart_size.enabled", false);
user_pref("browser.cache.disk.smart_size.first_run", false);
user_pref("browser.cache.memory.enable", true);
user_pref("browser.cache.memory.capacity", 131072);  // 128 MB RAM buffer

user_pref("browser.sessionstore.privacy_level", 2);
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("browser.sessionstore.enabled", false);

user_pref("signon.rememberSignons", false);
user_pref("signon.autofillForms", false);
user_pref("browser.formfill.enable", false);
user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("extensions.formautofill.creditCards.enabled", false);

user_pref("places.history.enabled", false);
user_pref("browser.urlbar.suggest.history", false);
user_pref("browser.urlbar.suggest.bookmark", false);

user_pref("network.cookie.lifetimePolicy", 2);    // Session cookies only
user_pref("network.cookie.cookieBehavior", 1);    // Block third-party cookies
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.history", true);
user_pref("privacy.clearOnShutdown.formdata", true);
user_pref("privacy.clearOnShutdown.downloads", true);
user_pref("privacy.clearOnShutdown.sessions", true);
user_pref("privacy.clearOnShutdown.offlineApps", true);

user_pref("dom.indexedDB.enabled", false);
user_pref("dom.storage.enabled", false);
user_pref("browser.pagethumbnails.capturing_disabled", true);
user_pref("browser.shell.checkDefaultBrowser", false);

// --- [2] KILL-SWITCH — cut all internet access if the proxy fails ---
//
// These two settings are critical:
//   failover_direct = false  → If the proxy is unreachable, Firefox does NOT
//                              fall back to a direct connection. Traffic stops.
//   proxy.type = 1           → Manual proxy; browser never auto-detects.
//
user_pref("network.proxy.failover_direct", false);  // ★ KILL-SWITCH
user_pref("network.proxy.type", 1);

// SOCKS5 → mafsal_client.py (localhost:1080)
user_pref("network.proxy.socks", "127.0.0.1");
user_pref("network.proxy.socks_port", 1080);
user_pref("network.proxy.socks_version", 5);
user_pref("network.proxy.socks_remote_dns", true);  // DNS also goes through the tunnel!

// HTTP/HTTPS via the same proxy (double assurance)
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", 1080);
user_pref("network.proxy.ssl", "127.0.0.1");
user_pref("network.proxy.ssl_port", 1080);

// Proxy bypass — localhost only (mafsal_client address)
user_pref("network.proxy.no_proxies_on", "127.0.0.1, localhost");

// --- [3] DNS ISOLATION ---
// DNS is forwarded through SOCKS5 (socks_remote_dns=true).
// DoH mode 2 (SOCKS first, DoH fallback) is a safe balance.
user_pref("network.trr.mode", 2);
user_pref("network.trr.uri", "https://mozilla.cloudflare-dns.com/dns-query");
user_pref("network.trr.bootstrapAddress", "1.1.1.1");
user_pref("network.trr.allow-rfc1918", false);
user_pref("network.dns.disableIPv6", true);           // ★ IPv6 leak prevention

// --- [4] WebRTC / IP LEAK PREVENTION ---
//
// WebRTC can expose your real IP independently of proxy settings.
// The three settings below close this channel completely.
//
user_pref("media.peerconnection.enabled", false);      // ★ Disable WebRTC entirely
user_pref("media.navigator.enabled", false);           // ★ Disable device enumeration
user_pref("media.peerconnection.ice.no_host", true);  // Block ICE host candidates
user_pref("media.peerconnection.ice.proxy_only", true); // Proxy-only ICE

// --- [5] FINGERPRINT RESISTANCE ---
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.firstparty.isolate", true);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);

user_pref("geo.enabled", false);
user_pref("dom.battery.enabled", false);
user_pref("device.sensors.enabled", false);
user_pref("dom.webaudio.enabled", false);
user_pref("canvas.poisondata", true);

// --- [6] TLS SECURITY ---
user_pref("security.tls.version.min", 3);              // TLS 1.2 minimum
user_pref("security.ssl.require_safe_negotiation", true);
user_pref("security.tls.enable_0rtt_data", false);    // Disable 0-RTT (replay risk)

// --- [7] TELEMETRY BLOCK ---
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.server", "");
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("browser.ping-centre.telemetry", false);
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("browser.discovery.enabled", false);
user_pref("extensions.pocket.enabled", false);
