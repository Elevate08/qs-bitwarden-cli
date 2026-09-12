import QtQuick
import qs.Commons
import qs.Ui
import "BitwardenModel.js" as Model

// Item-form custom fields. Bitwarden fixes a field's type when it is added;
// the value control then follows that type (text, masked, checkbox, or linked
// native field). Its label is read-only until the row's pencil action opens
// the separate rename controls, matching Bitwarden's browser form.
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
      readonly property bool editingLabel: editor.panel.formPicker === "customLabel:" + index
      width: editor.width
      spacing: Style.space(4)

      Row {
        visible: !fieldRow.editingLabel
        width: parent.width
        spacing: Style.space(6)

        Column {
          width: parent.width - editLabelButton.width - Style.space(6)
          spacing: Style.space(2)

          Text {
            textFormat: Text.PlainText
            width: parent.width
            text: String(fieldRow.modelData.name || "")
            color: editor.panel.fg
            font.family: editor.panel.fontFamily
            font.pixelSize: Style.font.bodySmall
            font.bold: true
            wrapMode: Text.Wrap
          }

          Text {
            textFormat: Text.PlainText
            text: editor.panel.customFieldTypeLabel(fieldRow.modelData.type) + " field"
            color: editor.panel.dim
            font.family: editor.panel.fontFamily
            font.pixelSize: Style.font.caption
          }
        }

        Button {
          id: editLabelButton
          anchors.verticalCenter: parent.verticalCenter
          iconText: "󰏫"
          tooltipText: Model.plainLabel("Edit label for " + String(fieldRow.modelData.name || "custom field"))
          fontFamily: editor.panel.fontFamily
          fontSize: Style.font.caption
          onClicked: editor.panel.beginCustomFieldLabelEdit(fieldRow.index)
        }
      }

      Column {
        visible: fieldRow.editingLabel
        width: parent.width
        spacing: Style.space(5)

        Text {
          textFormat: Text.PlainText
          text: "EDIT FIELD LABEL"
          color: editor.panel.dim
          font.family: editor.panel.fontFamily
          font.pixelSize: Style.font.caption
          font.bold: true
        }

        TextField {
          width: parent.width
          placeholderText: "Field label"
          text: editor.panel.formCustomFieldLabelDraft
          onTextChanged: editor.panel.formCustomFieldLabelDraft = text
          onAccepted: editor.panel.saveCustomFieldLabel(fieldRow.index)
        }

        Row {
          width: parent.width
          spacing: Style.space(5)

          Button {
            text: "Save label"
            iconText: "󰄬"
            selected: true
            accent: Color.accent
            enabled: editor.panel.formCustomFieldLabelDraft.trim() !== ""
            fontFamily: editor.panel.fontFamily
            fontSize: Style.font.caption
            onClicked: editor.panel.saveCustomFieldLabel(fieldRow.index)
          }

          Button {
            text: "Cancel"
            fontFamily: editor.panel.fontFamily
            fontSize: Style.font.caption
            onClicked: editor.panel.cancelCustomFieldLabelEdit()
          }

          Item { width: Style.space(4); height: 1 }

          Button {
            iconText: "󰆴"
            tooltipText: Model.plainLabel("Delete " + String(fieldRow.modelData.name || "custom field"))
            fontFamily: editor.panel.fontFamily
            fontSize: Style.font.caption
            onClicked: editor.panel.removeFormCustomField(fieldRow.index)
          }
        }
      }

      TextField {
        visible: !fieldRow.editingLabel
          && (Number(fieldRow.modelData.type) === 0 || Number(fieldRow.modelData.type) === 1)
        width: parent.width
        placeholderText: Number(fieldRow.modelData.type) === 1 ? "Hidden value" : "Value"
        password: Number(fieldRow.modelData.type) === 1 && !fieldRow.hiddenRevealed
        text: fieldRow.modelData.value === undefined || fieldRow.modelData.value === null
          ? "" : String(fieldRow.modelData.value)
        rightPadding: Number(fieldRow.modelData.type) === 1
          ? revealButton.width + Style.space(12) : horizontalPadding
        onTextChanged: editor.panel.setFormCustomFieldValue(fieldRow.index, text)

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
        visible: !fieldRow.editingLabel && Number(fieldRow.modelData.type) === 2
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
          editor.panel.setFormCustomFieldValue(fieldRow.index, fieldRow.booleanValue)
        }
      }

      Button {
        visible: !fieldRow.editingLabel && Number(fieldRow.modelData.type) === 3
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
        visible: !fieldRow.editingLabel && Number(fieldRow.modelData.type) === 3
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
              editor.panel.setFormCustomFieldLinkedId(fieldRow.index, modelData.id)
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
