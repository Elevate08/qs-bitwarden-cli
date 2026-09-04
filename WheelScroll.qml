import QtQuick

// Wheel scrolling for a Flickable, at a rate chosen here rather than inherited.
//
// Qt moves a Flickable by the platform's wheel-scroll-lines, which is tuned for
// a full-screen document and is a crawl in a panel three hundred pixels tall:
// several turns of the wheel to cross one screen of settings. The step below is
// a multiple of that, applied identically everywhere so no two views in the
// panel scroll at different speeds.
//
// Placed inside the Flickable it drives, which it takes as its target. It
// accepts the event, so the Flickable's own slower handling does not also run.
WheelHandler {
  id: root

  required property Flickable view
  // Pixels per wheel notch. A notch is 120 eighths-of-a-degree. Roughly twice
  // what Qt would move on its own -- enough that a screenful is a couple of
  // turns rather than half a dozen, and not so much that a notch overshoots
  // the thing being scrolled to. One number, one place; every view reads it.
  property real step: 90

  acceptedDevices: PointerDevice.Mouse | PointerDevice.TouchPad

  onWheel: function(event) {
    var notches = event.angleDelta.y / 120
    if (notches === 0) return

    // A touchpad sends many small deltas rather than whole notches, and
    // multiplying those the same way overshoots wildly. Scale the fractional
    // part as it comes; only whole notches get the full step.
    var limit = Math.max(0, root.view.contentHeight - root.view.height)
    var next = root.view.contentY - notches * root.step
    root.view.contentY = Math.max(0, Math.min(limit, next))
    event.accepted = true
  }
}
