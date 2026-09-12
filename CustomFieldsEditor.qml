import QtQuick
import qs.Commons
import qs.Ui
import "BitwardenModel.js" as Model

// Item-form custom fields. Bitwarden fixes a field's type when it is added;
// the value control then follows that type (text, masked, checkbox, or linked
// native field) while its label remains editable.
Column {
  id: editor

  required property var panel

  spacing: Style.space(7)

  PanelSectionHeader {
    text: "CUSTOM FIELDS"
    textFormat: Text.PlainText
    foreground: editor.panel.fg
    fontFamily: editor.panel.fontFamily
  }

  Repeater {
    id: customFieldEditorRepeater
    model: editor.panel.formCustomFields

    delegate: Column {
      id: fieldRow
      required property var modelData
      required property int index
      property bool booleanValue: editor.panel.customFieldBooleanValue(modelData.value)
      property bool hiddenRevealed: Boolean(modelData.revealed)
      property int linkedTarget: modelData.linkedId === undefined || modelData.linkedId === null
        ? -1 : Number(modelData.linkedId)
      width: editor.width
      spacing: Style.space(4)

      Row {
        width: parent.width
        spacing: Style.space(6)

        Text {
          textFormat: Text.PlainText
          width: parent.width - removeButton.width - Style.space(6)
          anchors.verticalCenter: parent.verticalCenter
          text: editor.panel.customFieldTypeLabel(fieldRow.modelData.type) + " field"
          color: editor.panel.dim
          font.family: editor.panel.fontFamily
          font.pixelSize: Style.font.caption
          font.bold: true
        }

        Button {
          id: removeButton
          iconText: "󰆴"
          tooltipText: Model.plainLabel("Delete " + String(fieldRow.modelData.name || "custom field"))
          fontFamily: editor.panel.fontFamily
          fontSize: Style.font.caption
          onClicked: editor.panel.removeFormCustomField(fieldRow.index)
        }
      }

      TextField {
        width: parent.width
        placeholderText: "Field label"
        text: String(fieldRow.modelData.name || "")
        onTextChanged: fieldRow.modelData.name = text
      }

      TextField {
        visible: Number(fieldRow.modelData.type) === 0 || Number(fieldRow.modelData.type) === 1
        width: parent.width
        placeholderText: Number(fieldRow.modelData.type) === 1 ? "Hidden value" : "Value"
        password: Number(fieldRow.modelData.type) === 1 && !fieldRow.hiddenRevealed
        text: fieldRow.modelData.value === undefined || fieldRow.modelData.value === null
          ? "" : String(fieldRow.modelData.value)
        rightPadding: Number(fieldRow.modelData.type) === 1
          ? revealButton.width + Style.space(12) : horizontalPadding
        onTextChanged: fieldRow.modelData.value = text

        Button {
          id: revealButton
          visible: Number(fieldRow.modelData.type) === 1
          anchors.right: parent.right
          anchors.rightMargin: Style.space(3)
          anchors.verticalCenter: parent.verticalCenter
          iconText: fieldRow.hiddenRevealed ? "󰈉" : "󰈈"
          tooltipText: fieldRow.hiddenRevealed ? "Hide value" : "Show value"
          fontFamily: editor.panel.fontFamily
          onClicked: {
            fieldRow.hiddenRevealed = !fieldRow.hiddenRevealed
            fieldRow.modelData.revealed = fieldRow.hiddenRevealed
          }
        }
      }

      Button {
        visible: Number(fieldRow.modelData.type) === 2
        width: parent.width
        text: fieldRow.booleanValue ? "Checked" : "Unchecked"
        iconText: fieldRow.booleanValue ? "󰄲" : "󰄱"
        selected: fieldRow.booleanValue
        accent: Color.accent
        leftAlign: true
        fontFamily: editor.panel.fontFamily
        fontSize: Style.font.bodySmall
        onClicked: {
          fieldRow.booleanValue = !fieldRow.booleanValue
          fieldRow.modelData.value = fieldRow.booleanValue
        }
      }

      Button {
        visible: Number(fieldRow.modelData.type) === 3
        width: parent.width
        text: editor.panel.customFieldLinkedLabel(fieldRow.linkedTarget)
        iconText: editor.panel.formPicker === "customLinked:" + fieldRow.index
          ? "\u{F0140}" : "\u{F0337}"
        selected: editor.panel.formPicker === "customLinked:" + fieldRow.index
        accent: Color.accent
        leftAlign: true
        fontFamily: editor.panel.fontFamily
        fontSize: Style.font.bodySmall
        onClicked: editor.panel.toggleFormPicker("customLinked:" + fieldRow.index)
      }

      Column {
        visible: Number(fieldRow.modelData.type) === 3
          && editor.panel.formPicker === "customLinked:" + fieldRow.index
        width: parent.width
        spacing: Style.space(2)

        Repeater {
          model: editor.panel.customFieldLinkedOptions(editor.panel.formTypeCode)
          delegate: FormPickerRow {
            required property var modelData
            width: fieldRow.width
            foreground: editor.panel.fg
            fontFamily: editor.panel.fontFamily
            label: modelData.label
            glyph: "\u{F0337}"
            picked: fieldRow.linkedTarget === Number(modelData.id)
            onActivated: {
              fieldRow.linkedTarget = Number(modelData.id)
              fieldRow.modelData.linkedId = Number(modelData.id)
              editor.panel.formPicker = ""
            }
          }
        }
      }

      PanelSeparator { width: parent.width }
    }
  }

  Button {
    visible: editor.panel.formPicker !== "customAdd"
    text: "Add custom field"
    iconText: "\u{F0415}"
    fontFamily: editor.panel.fontFamily
    fontSize: Style.font.bodySmall
    onClicked: editor.panel.formPicker = "customAdd"
  }

  Column {
    visible: editor.panel.formPicker === "customAdd"
    width: parent.width
    spacing: Style.space(6)

    Text {
      textFormat: Text.PlainText
      text: "FIELD TYPE"
      color: editor.panel.dim
      font.family: editor.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.bold: true
    }

    Flow {
      width: parent.width
      spacing: Style.space(5)

      Button {
        text: "Text"
        selected: editor.panel.formNewCustomFieldType === 0
        fontFamily: editor.panel.fontFamily
        fontSize: Style.font.caption
        onClicked: editor.panel.formNewCustomFieldType = 0
      }
      Button {
        text: "Hidden"
        selected: editor.panel.formNewCustomFieldType === 1
        fontFamily: editor.panel.fontFamily
        fontSize: Style.font.caption
        onClicked: editor.panel.formNewCustomFieldType = 1
      }
      Button {
        text: "Boolean"
        selected: editor.panel.formNewCustomFieldType === 2
        fontFamily: editor.panel.fontFamily
        fontSize: Style.font.caption
        onClicked: editor.panel.formNewCustomFieldType = 2
      }
      Button {
        visible: editor.panel.customFieldLinkedOptions(editor.panel.formTypeCode).length > 0
        text: "Linked"
        selected: editor.panel.formNewCustomFieldType === 3
        fontFamily: editor.panel.fontFamily
        fontSize: Style.font.caption
        onClicked: editor.panel.formNewCustomFieldType = 3
      }
    }

    Row {
      width: parent.width
      spacing: Style.space(6)

      TextField {
        width: parent.width - addButton.width - Style.space(6)
        placeholderText: "Field label"
        text: editor.panel.formNewCustomFieldName
        onTextChanged: editor.panel.formNewCustomFieldName = text
        onAccepted: editor.panel.addFormCustomField()
      }

      Button {
        id: addButton
        text: "Add"
        iconText: "\u{F0415}"
        selected: true
        accent: Color.accent
        fontFamily: editor.panel.fontFamily
        fontSize: Style.font.caption
        enabled: editor.panel.formNewCustomFieldName.trim() !== ""
        onClicked: editor.panel.addFormCustomField()
      }
    }

    Button {
      text: "Cancel"
      fontFamily: editor.panel.fontFamily
      fontSize: Style.font.caption
      onClicked: {
        editor.panel.formNewCustomFieldName = ""
        editor.panel.formNewCustomFieldType = 0
        editor.panel.formPicker = ""
      }
    }
  }
}
