// The remembered generator options are read back in QML's engine, from the
// settings object the shell hands over, so the round trip is pinned here too.
//
//   QT_QPA_PLATFORM=offscreen qmltestrunner -input tests/qml/tst_generator_options.qml
//
import QtQuick
import QtTest
import "../../BitwardenModel.js" as Model

TestCase {
  name: "GeneratorOptions"

  // As shell.json holds it: parsed JSON, carried in a `var` property.
  property var settings: ({})

  function test_saved_options_round_trip_through_a_var_property() {
    var chosen = Model.normalizeGeneratorOptions({ length: 24, special: true, minSpecial: 3 })
    settings = JSON.parse(JSON.stringify({ generatorOptions: Model.generatorOptionsToStore(chosen) }))
    compare(JSON.stringify(Model.restoreGeneratorOptions(settings.generatorOptions)), JSON.stringify(chosen))
  }

  function test_nothing_saved_keeps_the_defaults() {
    settings = ({})
    compare(JSON.stringify(Model.restoreGeneratorOptions(settings.generatorOptions)),
      JSON.stringify(Model.generatorDefaults()))
  }

  function test_unreadable_values_fall_back_to_the_defaults() {
    settings = JSON.parse('{"generatorOptions":{"length":"30","special":"true","type":"pin","separator":"--"}}')
    var o = Model.restoreGeneratorOptions(settings.generatorOptions)
    compare(o.length, 14)
    compare(o.special, false)
    compare(o.type, "password")
    compare(o.separator, "-")
  }
}
