import QtQuick
import QtTest
import "../../BitwardenModel.js" as Model

TestCase {
  name: "SshItems"

  function test_sanitized_items_are_filterable_and_public() {
    var items = Model.parseSanitizedItems(JSON.stringify({
      items: [{ id: "login", type: 1, name: "Login", login: { username: "u" } }],
      sshKeys: [{ id: "ssh", type: 5, name: "Deploy", favorite: true,
        sshKey: { publicKey: "ssh-ed25519 AAAA", fingerprint: "SHA256:fp" } }]
    }))
    compare(items.length, 2)
    compare(Model.filterItems(items, "AAAA", "all", "all", "all").length, 1)
    compare(Model.filterItems(items, "", "sshKey", "all", "all")[0].id, "ssh")
    verify(Model.itemDetailFromObject(items[1].rawObject).password === "")
  }

  function test_ssh_generic_actions_fail_closed() {
    compare(Model.buildCreatePayload(5, "Deploy"), null)
    compare(Model.getItemCommand("ssh", 5).length, 0)
    compare(Model.editItemCommand("ssh", 5).length, 0)
    compare(Model.deleteItemCommand("ssh", 5).length, 0)
  }
}
