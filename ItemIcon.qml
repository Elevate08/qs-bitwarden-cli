import QtQuick
import QtQuick.Window
import "BitwardenModel.js" as Model

// An item's icon, drawn as Bitwarden's clients draw it: a login's website
// icon when "Show website icons" is on and the icon service has one, the
// glyph from itemIconGlyph() (type, app or card-brand mark) otherwise. The
// glyph stays until the image has loaded, and comes back if it fails.
Item {
  id: icon

  property var item: null
  property bool showWebsiteIcons: false
  property string serverUrl: ""
  // Spins the reload glyph while the row is being saved.
  property bool pending: false
  property color color: "white"
  property color pendingColor: color
  property string fontFamily: ""
  property int size: 20
  property int glyphSize: Math.round(size * 0.85)

  readonly property string imageUrl: pending ? ""
    : Model.websiteIconUrl(item, showWebsiteIcons, serverUrl)
  // The image's size in device pixels on this item's screen.
  readonly property int pixelSize: Math.ceil(size * Math.max(1, Screen.devicePixelRatio || 1))
  // The icon itself, as a data URL, once fetched and checked; "" until then
  // and where there is none. The Image is never given `imageUrl`: it would
  // log that URL, which names the site, whenever the service has no icon,
  // and decode whatever came back (Model.websiteIconDataUrl()).
  property string imageData: ""
  readonly property bool imageShown: imageData !== "" && favicon.status === Image.Ready

  // Also at creation: the binding's first value is a change from "".
  onImageUrlChanged: fetchIcon()

  function fetchIcon() {
    var url = imageUrl
    var known = url === "" ? "" : Model.websiteIconCached(url)
    imageData = known === undefined ? "" : known
    if (known !== undefined) return
    var generation = Model.websiteIconGenerationNow()
    var xhr = new XMLHttpRequest()
    xhr.responseType = "arraybuffer"
    xhr.onreadystatechange = function() {
      if (xhr.readyState !== XMLHttpRequest.DONE) return
      // No answer at all (offline) is not "no icon": asked again next time.
      if (xhr.status === 0) return
      var data = xhr.status === 200 ? Model.websiteIconDataUrl(xhr.response) : ""
      Model.rememberWebsiteIcon(url, data, generation)
      // This row may be gone, or showing another item, by now.
      try {
        if (icon.imageUrl === url && Model.websiteIconCached(url) === data) icon.imageData = data
      } catch (e) {}
    }
    xhr.open("GET", url)
    xhr.send()
  }

  implicitWidth: size
  implicitHeight: size

  Text {
    id: glyph
    anchors.centerIn: parent
    width: parent.width
    visible: !icon.imageShown
    textFormat: Text.PlainText
    text: icon.pending ? "󰑐" : Model.itemIconGlyph(icon.item, icon.showWebsiteIcons)
    color: icon.pending ? icon.pendingColor : icon.color
    font.family: icon.fontFamily
    font.pixelSize: icon.glyphSize
    // Centred so it spins on its own axis.
    horizontalAlignment: Text.AlignHCenter
    transformOrigin: Item.Center

    RotationAnimation on rotation {
      running: icon.pending
      loops: Animation.Infinite
      from: 0
      to: 360
      duration: 900
    }
  }

  Image {
    id: favicon
    // Whole pixels: a half-pixel offset resamples the image again.
    x: Math.round((parent.width - width) / 2)
    y: Math.round((parent.height - height) / 2)
    width: icon.size
    height: icon.size
    visible: icon.imageShown
    source: icon.imageData
    // Off the GUI thread, and kept: a list scrolls back past the same rows.
    asynchronous: true
    cache: true
    fillMode: Image.PreserveAspectFit
    smooth: true
    // Decoded at the screen pixels it covers, so the service's 32-64 px icon
    // is scaled once, smoothly, and drawn about 1:1. sourceSize is in device
    // pixels for a raster image: plain `size` decoded a 20 px image that a
    // 1.33x display then stretched to 27, which is what looked blurry.
    sourceSize.width: icon.pixelSize
    sourceSize.height: icon.pixelSize
  }
}
