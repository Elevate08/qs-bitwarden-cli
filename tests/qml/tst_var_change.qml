import QtQuick
import QtTest

// The service counts replacements of its list and of the learned picks
// (onItemsChanged / onAssociationsChanged) to know whether the suggestions on
// show still answer the question being asked. That rests on a `property var`
// notifying on every assignment of another array or object, equal in content
// or not, and staying quiet for the same one.
TestCase {
  name: "VarChange"

  Item {
    id: holder
    property var items: []
    property var associations: ({ version: 1, keys: {} })
    property int gen: 0
    onItemsChanged: gen += 1
    onAssociationsChanged: gen += 1
  }

  function test_assigning_another_array_or_object_notifies() {
    var before = holder.gen
    holder.items = [{ id: "a" }]
    compare(holder.gen, before + 1)
    holder.items = [{ id: "a" }]
    compare(holder.gen, before + 2, "an equal array that is another array notifies")
    holder.items = []
    holder.items = []
    compare(holder.gen, before + 4, "an empty array in place of an empty array notifies")
    holder.associations = { version: 1, keys: {} }
    compare(holder.gen, before + 5, "an equal object that is another object notifies")
  }

  function test_assigning_the_same_one_does_not() {
    var list = [{ id: "a" }]
    holder.items = list
    var before = holder.gen
    holder.items = list
    compare(holder.gen, before, "nothing was replaced")
  }

  function test_the_handler_has_run_before_the_assignment_returns() {
    var before = holder.gen
    holder.items = [{ id: "b" }]
    // No event loop turn in between: the count a match is keyed by is
    // already the new one when the next line of the caller runs.
    compare(holder.gen, before + 1)
  }
}
