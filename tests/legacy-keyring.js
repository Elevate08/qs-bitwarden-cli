// Writers for the keyring entries versions before the envelope kept, which the
// panel now only reads, migrates and deletes. Tests use them to build an old
// install's keyring.

function legacyKeyring(Model) {
  const store = (label, account) => ["bash", "-c", Model.keyringStoreScript(label, account)]
  return {
    storeMasterPassword: () => store("Bitwarden Master Password (fingerprint unlock)", Model.KEYRING_MASTER),
    storeFidoPassword: () => store("Bitwarden Master Password (FIDO2 unlock)", Model.KEYRING_FIDO),
    // AES-256-CBC under a PBKDF2 key from the PIN, as pinUnlockCommand() reads it.
    storePin: () => ["bash", "-c", Model.cappedScript("printf '%s' \"$" + Model.KEYRING_SECRET_ENV + "\""
      + " | openssl enc -aes-256-cbc -pbkdf2 -iter " + Model.PIN_ITERATIONS
      + " -md sha256 -salt -pass env:" + Model.PIN_ENV + " -base64 -A"
      + " | secret-tool store --label=" + Model.shellQuote("Bitwarden Master Password (PIN unlock)")
      + Model.keyringAttributes(Model.KEYRING_PIN))]
  }
}

module.exports = { legacyKeyring }
