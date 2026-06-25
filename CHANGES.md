# Previous Versions

* [Version 2.1.0 to 2.2.0](./docs/changes/2.2.0.md)
* [Version 2.2.0 to 2.3.0](./docs/changes/2.3.0.md)
* [Version 2.3.0 to 2.4.0](./docs/changes/2.4.0.md)
* [Version 2.4.0 to 2.5.0](./docs/changes/2.5.0.md)
* [Version 2.5.0 to 2.5.1](./docs/changes/2.5.1.md)
* [Version 2.5.1 to 2.6.0](./docs/changes/2.6.0.md)
* [Version 2.6.0 to 2.7.0](./docs/changes/2.7.0.md)
* [Version 2.7.0 to 2.8.0](./docs/changes/2.8.0.md)
* [Version 2.8.0 to 2.9.0](./docs/changes/2.9.0.md)
* [Version 2.9.0 to 2.9.1](./docs/changes/2.9.1.md)
* [Version 2.9.1 to 2.9.2](./docs/changes/2.9.2.md)
* [Version 2.9.2 to 2.10.0](./docs/changes/2.10.0.md)
* [Version 2.10.0 to 2.11.0](./docs/changes/2.11.0.md)
* [Version 2.11.0 to 2.12.0](./docs/changes/2.12.0.md)
* [Version 2.12.0 to 2.12.1](./docs/changes/2.12.1.md)
* [Version 2.12.1 to 2.13.0](./docs/changes/2.13.0.md)
* [Version 2.13.0 to 2.13.1](./docs/changes/2.13.1.md)
* [Version 2.13.1 to 2.13.2](./docs/changes/2.13.2.md)
* [Version 2.13.2 to 2.14.0](./docs/changes/2.14.0.md)
* [Version 2.14.0 to 2.15.0](./docs/changes/2.15.0.md)
* [Version 2.15.0 to 2.16.0](./docs/changes/2.16.0.md)
* [Version 2.16.0 to 2.17.0](./docs/changes/2.17.0.md)
* [Version 2.17.0 to 2.17.1](./docs/changes/2.17.1.md)

# Latest Version

* **[Version 2.17.1 to 2.18.0](./docs/changes/2.18.0.md)**

# Planned for Next Version

## Bug Fixes

* [GH-899](https://github.com/apache/mina-sshd/issues/899) Fix `ProcessShellFactory` on Linux
* [GH-902](https://github.com/apache/mina-sshd/pull/902) Fix client-side handling of sk-* public key signatures (also in the agent interfaces)
* Limit size of decompressed SSH packets
* Improve checking SSH user certificates in public-key authentication
* Improve handling of repository paths in `sshd-git` on Windows
* Validate file names in SCP
* Escape newlines in filenames in the SCP protocol
* Restrict JGit commands accessible via `GitPgmCommandFactory` in `sshd-git`

## New Features


## Potential Compatibility Issues

### Restrict JGit commands accessible via `GitPgmCommandFactory` in `sshd-git`

Bundle `sshd-git` contains a `GitPgmCommandFactory` that can be configured for an Apache MINA SSHD server.
It enables remote execution of git commands via JGit.

However, running arbitrary git commands remotely is an exotic use case, and some commands (like
`git archive --format zip --output somefile.zip` or also `git clone`  or `git checkout`) could even create
files on the server. This should be only allowed in an OS-level chrooted environment, which Apache MINA
SSHD does not and cannot provide.

We have therefore limited the available commands to a small set of whitelisted git commands that might
be useful as maintenance commands for authorized power users on a git server implemented based on `sshd-git`.
The command are: `archive`, `blame`, `branch`, `describe`, `diff`, `gc`, `log`, `reflog`, `show`, and `status`.
All these commands can be executed from an client via `git --git-dir <repo> <command> <args>`, where `<repo>`
is the server-side name of the git repository (its local path on the server relative to the configured
root), `<command>` is the command name (e.g., `archive`) and `<args>` are the command arguments. Results are
sent back via the command output streams (output or error streams) and are thus sent back to the client.
For the `archive`command, the `--output` (or `-o`) argument is ignored; the archive is always returned via
the command's output stream and this is also sent to the client.

Applications that might have relied on the ability to run other JGit command remotely may no longer work.
Either implement your own dedicated command factory to enable accesss to certain commands, or set the
property `GitModuleProperties.RESTRICT_COMMANDS` to `false` on the server-side `SshServer` (for all sessions)
or on particular `ServerSession`s (for particular individual sessions) to re-enable access to _all_ commands
supported by JGit.

## Major Code Re-factoring

