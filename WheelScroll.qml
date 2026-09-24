import QtQuick

// Wheel scrolling for the Flickable it sits in, at one faster rate shared by
// every view (Qt's default step crawls in a small panel). Accepts the event
// so the Flickable's own handling does not also run.
WheelHandler {
  id: root

  required property Flickable view
  // Pixels per wheel notch (120 angle-delta units); about twice Qt's default.
  property real step: 90

  acceptedDevices: PointerDevice.Mouse | PointerDevice.TouchPad

  onWheel: function(event) {
    var notches = event.angleDelta.y / 120
    if (notches === 0) return

    // Touchpads send fractional notches, which scale linearly.
    var limit = Math.max(0, root.view.contentHeight - root.view.height)
    var next = root.view.contentY - notches * root.step
    root.view.contentY = Math.max(0, Math.min(limit, next))
    event.accepted = true
  }
}
