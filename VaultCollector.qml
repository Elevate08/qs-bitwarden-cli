import QtQuick

// A VaultProcess's stdout or stderr, read like Quickshell's StdioCollector:
// `text` once the run has ended, then `streamFinished`.
QtObject {
  property string text: ""
  // Accepted for StdioCollector compatibility; text arrives whole anyway.
  property bool waitForEnd: true
  signal streamFinished()
}
