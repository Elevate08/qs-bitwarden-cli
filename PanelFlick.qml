import QtQuick
import QtQuick.Controls

// A vertically scrolling view of the panel: clipped, stopping at its bounds,
// with a scrollbar when needed and the panel's wheel rate (WheelScroll).
Flickable {
  id: flick
  contentWidth: width
  clip: true
  boundsBehavior: Flickable.StopAtBounds
  flickableDirection: Flickable.VerticalFlick
  ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

  WheelScroll { view: flick }
}
