import QtQuick
import Quickshell.Io

// A Process read for its whole stdout: `collected` hands it over once the
// stream has ended.
Process {
  id: proc
  signal collected(string text)
  stdout: StdioCollector {
    waitForEnd: true
    onStreamFinished: proc.collected(text)
  }
}
