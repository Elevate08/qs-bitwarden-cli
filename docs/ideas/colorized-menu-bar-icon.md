# Colorized Menu-Bar Icon

Status: refined design proposal, implementation approved

## Problem Statement

How might we let users who run a colorized desktop theme make the Bitwarden
menu-bar icon feel native to that theme without introducing arbitrary color
configuration or weakening the icon's status indicators?

## Recommended Direction

Add a single **Colorize menu-bar icon** toggle to the existing General settings
screen. The setting is off by default, preserving the current appearance. When
enabled, the primary shield glyph uses Omarchy's live `Color.accent` value;
the preference stores only the boolean choice, so changing the desktop theme
automatically changes the icon color.

Only the primary shield is colorized. The locked-state padlock, missing-tool
badge, and error/setup indicators retain their existing foreground and urgent
colors. This keeps the accent color as personalization while preserving the
meaning of exceptional states.

The feature fits the existing settings path: schema and manifest metadata,
`omarchy bar set` persistence, live shell reload, and the current settings-row
keyboard interaction. No custom RGB picker or new dependency is needed.

## Key Assumptions to Validate

- [ ] Users want the active theme accent specifically, rather than an
  independently chosen RGB value — validate with the first implementation and
  feedback from users who requested colorization.
- [ ] Keeping urgent/error badges independent is sufficient to preserve state
  recognition — verify visually in locked, setup-required, and error states.
- [ ] A boolean toggle is discoverable enough in the existing General section
  — confirm the label and description are clear in the settings screenshot or
  runtime review.

## MVP Scope

- Add `colorizeIcon` as a boolean setting, defaulting to `false`.
- Add a General settings row labeled **Colorize menu-bar icon** with a
  description explaining that it follows the active theme accent.
- Bind the primary menu-bar shield color to `Color.accent` when enabled and to
  the existing bar foreground when disabled.
- Leave status badges and urgent/error colors unchanged.
- Add model, manifest, persistence, malformed-value, and QML wiring tests.
- Verify that theme changes are reflected after the shell reloads the panel.

## Not Doing (and Why)

- Arbitrary color picker or hex input — conflicts with the theme-derived goal
  and adds validation and contrast problems.
- Multiple palette choices — the accent is the one semantic theme color users
  are most likely asking for; broader palettes can follow if demand appears.
- Per-state color customization — risks making locked and error states harder
  to recognize.
- Changing the panel's internal icon, controls, or status badges — the request
  is specifically about the menu-bar icon's primary glyph.

## Open Questions

- Should the setting be called **Colorize menu-bar icon** or **Use theme accent
  for icon**? The former is more approachable; the latter is more explicit.
- Does the active accent maintain adequate contrast across the supported Omarchy
  themes, especially in light themes?
