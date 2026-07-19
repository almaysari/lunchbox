// Shared process bootstrap: initialize the encryption keyring EXACTLY the way
// the server does, for CLI entrypoints that touch encrypted state.
//
// Root cause this fixes (proven on the real tenant): server.js was the ONLY
// caller of cryptoCore.init(); every CLI diagnostic that decrypts (e.g.
// zoho-path-diagnose) ran with an EMPTY keyring, so decrypt() threw
// "No encryption key for version k1" in the CLI process on every tenant —
// contaminating Test A with a tool artifact while the server's own keyring was
// perfectly healthy. One bootstrap, used by server and CLIs alike, makes that
// class of divergence impossible.
const path = require('path');
const { loadEnv, validateSecrets, encryptionKeyring } = require('./env');
const cryptoCore = require('./crypto');

function initCryptoFromEnv(baseDir = path.join(__dirname, '..')) {
  const cfg = loadEnv(baseDir);
  const errors = validateSecrets(cfg);
  if (errors.length) {
    throw new Error('secrets not configured for this process: ' + errors.join(' | '));
  }
  cryptoCore.init(encryptionKeyring(cfg), cfg.MADAR_SESSION_SECRET, cfg.MADAR_CSRF_SECRET);
  return cfg;
}

module.exports = { initCryptoFromEnv };
