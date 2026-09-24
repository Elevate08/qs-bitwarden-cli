pragma Singleton
import QtQuick

// Stand-in for the Omarchy shell's Style: the vault service only sizes the
// filter drawer with it, and CI has no Omarchy shell to borrow it from.
QtObject {
  function space(n) { return n }
}
