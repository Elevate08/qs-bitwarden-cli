#!/usr/bin/env node
// Tests for the generator's option handling. Generation itself is `bw generate`;
// what is worth testing is that we never hand it a combination it rejects.
//
//   node tests/generator.test.js

const fs = require("fs")
const path = require("path")
const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.generateCommand = generateCommand
  exports.normalizeGeneratorOptions = normalizeGeneratorOptions
  exports.generatorDefaults = generatorDefaults
  exports.generatorStrength = generatorStrength
`)(Model)

let pass = 0
const failures = []
const check = (l, ok, d) => ok ? pass++ : failures.push(`${l}\n    ${d}`)
const args = o => Model.generateCommand(o).join(" ")

// `bw generate` errors if every character set is off; fall back rather than fail.
const none = Model.normalizeGeneratorOptions({ uppercase: false, lowercase: false, numbers: false, special: false })
check("all character sets off falls back to lowercase",
  none.lowercase === true, JSON.stringify(none))

// Requiring more special/numeric characters than the length allows is impossible.
const tight = Model.normalizeGeneratorOptions({ length: 5, numbers: true, minNumber: 9, special: true, minSpecial: 9 })
check("length grows to fit the required character minimums",
  tight.length >= tight.minNumber + tight.minSpecial, JSON.stringify(tight))

// Minimums for a disabled set would be rejected by bw.
const noNums = Model.normalizeGeneratorOptions({ numbers: false, minNumber: 5, special: false, minSpecial: 5 })
check("minimums are zeroed for disabled character sets",
  noNums.minNumber === 0 && noNums.minSpecial === 0, JSON.stringify(noNums))
check("disabled sets emit no minimum flags",
  !args({ numbers: false, special: false }).includes("--minNumber")
  && !args({ numbers: false, special: false }).includes("--minSpecial"),
  args({ numbers: false, special: false }))

// Clamping to the documented CLI limits.
for (const [k, v, lo, hi] of [["length", 1, 5, 128], ["length", 999, 5, 128],
                              ["words", 1, 3, 20], ["words", 99, 3, 20],
                              ["minNumber", -3, 0, 9], ["minSpecial", 99, 0, 9]]) {
  const got = Model.normalizeGeneratorOptions({ [k]: v, numbers: true, special: true })[k]
  check(`${k}=${v} clamps into [${lo}, ${hi}]`, got >= lo && got <= hi, `got ${got}`)
}

// Passphrase mode must not leak password-only flags, and vice versa.
const pp = args({ type: "passphrase", words: 5, capitalize: true, includeNumber: true })
check("passphrase passes --passphrase and word options",
  pp.includes("--passphrase") && pp.includes("--words 5") && pp.includes("--capitalize") && pp.includes("--includeNumber"), pp)
check("passphrase omits password-only flags",
  !pp.includes("--length") && !pp.includes("--minNumber") && !pp.includes("--uppercase"), pp)
const pw = args({ type: "password" })
check("password omits passphrase-only flags",
  !pw.includes("--passphrase") && !pw.includes("--words") && !pw.includes("--capitalize"), pw)

check("an empty separator falls back rather than producing a bare flag",
  Model.normalizeGeneratorOptions({ separator: "" }).separator === "-",
  Model.normalizeGeneratorOptions({ separator: "" }).separator)

// Strength must move in the right direction, or the meter misleads.
const s = o => Model.generatorStrength(o).bits
check("longer passwords score higher", s({ length: 32 }) > s({ length: 8 }), `${s({length:32})} vs ${s({length:8})}`)
check("more character sets score higher",
  s({ length: 16, special: true }) > s({ length: 16, special: false }),
  `${s({length:16,special:true})} vs ${s({length:16,special:false})}`)
check("more words score higher", s({ type: "passphrase", words: 8 }) > s({ type: "passphrase", words: 3 }),
  `${s({type:"passphrase",words:8})} vs ${s({type:"passphrase",words:3})}`)
check("strength fraction stays within 0..1",
  [{}, { length: 128, special: true }, { length: 5 }].every(o => {
    const f = Model.generatorStrength(o).fraction; return f >= 0 && f <= 1 }), "out of range")

check("defaults are a fresh object each call",
  Model.generatorDefaults() !== Model.generatorDefaults(), "same reference returned")

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
