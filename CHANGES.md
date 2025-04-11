# Previous Versions

* [Change Notes for Version 2](./docs/changes/version2.md)

# Version 3

** This is work in progress.**  Version 3 contains many API breaks from version 2. When we release it, there will be a japicmp report.

Version 3 includes all the features and bug fixes of version 2, including the [latest ones](https://github.com/apache/mina-sshd/blob/master/CHANGES.md#planned-for-next-version).

## Major Code Re-factoring

* The `AbstractSession` has been completely refactored. Most of its code has been moved out of this class into separate filters in a filter chain. For details, see the [technical documentation](./docs/technical/filters.md).
* Handling of global requests has been moved from `AbstractSession` to the `ConnectionService`.
* KEX temporarily closes `RemoteWindow`s, preventing data to be written in that way until KEX is over. Version 2 blocked threads in a different, more convoluted, and fragile way.

## New Features

* Random padding on SSH packets as suggested by [RFC 4253, section 6](https://datatracker.ietf.org/doc/html/rfc4253#section-6).
* New event callback `SessionListener.sessionStarting()`. See the [filter documentation](./docs/technical/filters.md). `SessionListener.sessionEstablished()` was removed; it was called from the constructor of `AbstractSession` at a time when the object was not yet fully initialized.