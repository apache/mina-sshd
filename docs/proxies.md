# Proxies

## SSH Jumps

The SSH client can be configured to use SSH jumps.  A *jump host* (also known as a *jump server*) is an 
intermediary host or an SSH gateway to a remote network, through which a connection can be made to another 
host in a dissimilar security zone, for example a demilitarized zone (DMZ). It bridges two dissimilar 
security zones and offers controlled access between them.

Starting from SSHD 2.6.0, the *ProxyJump* host configuration entry is honored when using the `SshClient`
to connect to a host.  The `SshClient` built by default reads the `~/.ssh/config` file. The various CLI clients
also honor the `-J` command line option to specify one or more jumps.

In order to manually configure jumps, you need to build a `HostConfigEntry` with a `proxyJump` and use it
to connect to the server:
```
ConnectFuture future = client.connect(new HostConfigEntry(
        "", host, port, user,
        proxyUser + "@" + proxyHost + ":" + proxyPort));
```

The configuration options specified in the configuration file for the jump hosts are also honored. 
