This module provides two command factories for git over SSH.
It uses JGit to implement the git functionality.

The GitPackCommand implements basic git push and fetch support
via git-receive-pack and git-upload-pack for an SSH git server.

The GitPgmCommand provides remote executon of git commands, so
clients can execute git commands on a server. This is by default
limited to non-invasive commands that might make sense on a git
server. The property GitModuleProperties.RESTRICT_COMMANDS can be
set to false on a server session to allow execution of arbitrary
git commands (if supported by JGit), but this is not recommended.

Finally, there is support for client-side git-over-SSH though the
GitSshdSession. However, note that JGit includes in its bundle
org.eclipse.jgit.ssh.apache its own git-over-SSH implementation
based on Apache MINA SSHD.