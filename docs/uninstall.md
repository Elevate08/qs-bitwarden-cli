# Uninstall

**Turn the SSH agent off first, if you had it on**, and press **Remove Plugin
Data** on the settings screen. Between them those clear everything this plugin
put outside its own folder: the helper stops cleanly and takes its socket,
FIFO and routing file with it, and the button clears the keyring entries, the
learned suggestions and the exported public keys. Both have to happen before
the next step, because `omarchy plugin remove` has no uninstall hook -- once
the folder is gone there is no code left to run.

```bash
omarchy plugin remove io.github.elevate08.qs-bitwarden-cli
```

That removes the plugin folder and its bar entry. If you skipped the two steps
above, or you are cleaning up after a plugin that is already gone, this is the
same work by hand:

```bash
# Session key, and the master password stored for PIN/fingerprint unlock
secret-tool clear service qs-bitwarden-cli

# Learned window-title -> vault item suggestions
rm -rf "${XDG_STATE_HOME:-$HOME/.local/state}/qs-bitwarden-cli"

# Settings block: already gone. `omarchy plugin remove` takes the bar entry
# and its settings with it. If a stale one is left -- from a plugin removed
# some other way -- clear it through the shell, never by editing the file:
#   omarchy plugin disable io.github.elevate08.qs-bitwarden-cli

# SSH agent, if you used it: the exported public keys and the routing file
rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/qs-bitwarden-cli/ssh"
rm -f ~/.config/uwsm/env.d/50-qs-bitwarden-ssh-agent
```

**Do not hand-edit `~/.config/omarchy/shell.json`.** On many setups it is not a
regular file: Omarchy configs are commonly managed with `stow` or another
dotfile manager, which puts a symlink there pointing into a repository. Deleting
"the file" then deletes the link, the shell falls back to its built-in defaults,
and every plugin you had configured disappears at once -- not just this one. The
config itself is unharmed, sitting in the repository the link pointed at, but
working that out from an empty bar is not a pleasant few minutes. Every command
above goes through the shell or touches only this plugin's own paths.

The agent's socket, FIFO and lock under `$XDG_RUNTIME_DIR` are removed when the
helper shuts down, which is what turning the agent off does. Removing the
plugin while the agent is still running kills the helper instead, so those
three files are left until you log out and the tmpfs goes with the session; a
stale socket at the routed path is harmless but answers nothing. Deleting the
directory by hand is safe once no helper is running.

Two more paths are written but need no cleaning up, because neither outlives
the moment it is used: the session handoff file under `$XDG_RUNTIME_DIR`, which
is read once and deleted and is on a tmpfs that goes with the login session,
and a `.qsbw-` staging directory inside your download folder, which exists only
for the length of an attachment download and is removed however that download
ends. Saved attachments themselves stay where you saved them, mode `600`.

Beyond those, the plugin writes nothing outside the paths above and your
`shell.json` entry, and it never modifies your Bitwarden vault on removal. Your vault is untouched -- log
out of the `bw` CLI separately with `bw logout` if you also want that cleared.

---
