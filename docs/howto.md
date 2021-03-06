# HOWTO(s)

This section contains some useful "cookbook recipes" for getting the most out of the code. Please note that it does **not** covers code samples that already appear in the previous sections - such as creating sessions, managing authentication, 3-way SCP, mounting file systems via SFTP, etc... Instead, it focuses on more "exotic" implementations that are not usually part of the normal SSH flow.

## [Endless tarpit](https://nullprogram.com/blog/2019/03/22/)

In order to achieve this one needs to use a `ReservedSessionMessagesHandler` on the server side that overrides the session identification and KEX message callbacks as follows:

* When `sendIdentification` callback is invoked

    * Check if you wish to trap the peer into the endless tarpit - if not, then return `null`
    
    * Spawn a thread that will feed the peer session with periodic infinite data.
    
    * Return a never succeeding `IoWriteFuture` - see `EndlessWriteFuture` in *sshd-contrib* package for such an implementation
    
* When `sendKexInitRequest` callback is invoked

    * Check if you wish to trap the peer into the endless tarpit - if not, then return `null`

    * Return an `IoWriteFuture` that "succeeds" immediately - see `ImmediateWriteFuture` in *sshd-contrib* package for such an implementation.

The idea is to prevent the normal session establish flow by taking over the initial handshake identification and blocking the initial KEX message from the server.

A sample implementation can be found in the `EndlessTarpitSenderSupportDevelopment` class in the *sshd-contrib* package *test* section.