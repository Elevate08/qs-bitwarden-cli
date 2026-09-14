import QtQuick

// The vault, once per shell.
//
// Omarchy builds its bar once per monitor, so Panel.qml -- the bar widget -- is
// instantiated once per monitor as well. Everything that must exist exactly
// once no matter how many monitors are attached lives here instead: the shell
// loads a plugin's `service` entry point a single time and hands the same
// object to every bar copy through `bar.shell.serviceFor()`. Each Panel.qml is
// a view of this object (issue #30).
//
// Where the shared service cannot be reached, a view creates a private one
// (Model.vaultHostDecision), so this file must also work as one view's own
// vault. A private host is marked so that nothing here assumes it is alone.
Item {
  id: vault

  // Injected by the shell's service loader. A private host has neither.
  property var shell: null
  property var manifest: null

  // True when a view created this instance for itself because the shared
  // service was unavailable.
  property bool privateHost: false

  // -------------------------------------------------------------------------
  // Views
  // -------------------------------------------------------------------------
  //
  // Every live bar copy attached to this vault, in attach order. A view
  // attaches once it has resolved its host and detaches when it is destroyed --
  // a monitor unplugged takes its view with it and leaves the vault running.
  property var views: []
  readonly property int viewCount: views.length

  function attachView(view) {
    if (!view || views.indexOf(view) !== -1) return
    views = views.concat([view])
    if (view.settings) updateSettings(view.settings)
  }

  function detachView(view) {
    var index = views.indexOf(view)
    if (index === -1) return
    var next = views.slice()
    next.splice(index, 1)
    views = next
  }

  // -------------------------------------------------------------------------
  // Settings
  // -------------------------------------------------------------------------
  //
  // The plugin's settings are its bar entry's inline object in shell.json. A
  // service is handed only a snapshot of the shell config at load, which would
  // go stale on the first edit, so the views -- whose `settings` the bar keeps
  // current -- push them here instead. `allowMultiple` is false, so every view
  // carries the same entry and whichever pushed last is authoritative.
  property var settings: ({})

  function updateSettings(next) {
    settings = next || ({})
  }

  function setting(name, fallback) {
    var value = settings ? settings[name] : undefined
    return value === undefined || value === null ? fallback : value
  }
}
