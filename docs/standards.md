# Supported standards

## Reference implementation documentation
* [RFC 4251 - The Secure Shell (SSH) Protocol Architecture](https://tools.ietf.org/html/rfc4251)
* [RFC 4252 - The Secure Shell (SSH) Authentication Protocol](https://tools.ietf.org/html/rfc4252)
* [RFC 4253 - The Secure Shell (SSH) Transport Layer Protocol](https://tools.ietf.org/html/rfc4253)
* [RFC 4254 - The Secure Shell (SSH) Connection Protocol](https://tools.ietf.org/html/rfc4254)
* [RFC 4256 - Generic Message Exchange Authentication for the Secure Shell Protocol (SSH)](https://tools.ietf.org/html/rfc4256)
* [RFC 4335 - The Secure Shell (SSH) Session Channel Break Extension](https://tools.ietf.org/html/rfc4335)
* [RFC 4344 - The Secure Shell (SSH) Transport Layer Encryption Modes](https://tools.ietf.org/html/rfc4344)
* [RFC 4345 - Improved Arcfour Modes for the Secure Shell (SSH) Transport Layer Protocol](https://tools.ietf.org/html/rfc4345)
* [RFC 4419 - Diffie-Hellman Group Exchange for the Secure Shell (SSH) Transport Layer Protocol](https://tools.ietf.org/html/rfc4419)
* [RFC 4716 - The Secure Shell (SSH) Public Key File Format](https://tools.ietf.org/html/rfc4716)
* [RFC 5208 - Public-Key Cryptography Standards (PKCS) #8 - version 1.2](https://tools.ietf.org/html/rfc5208)
* [RFC 5480 - Elliptic Curve Cryptography Subject Public Key Information](https://tools.ietf.org/html/rfc5480)
* [RFC 5647 - AES Galois Counter Mode for the Secure Shell Transport Layer Protocol](https://tools.ietf.org/html/rfc5647)
* [RFC 5656 - Elliptic Curve Algorithm Integration in the Secure Shell Transport Layer](https://tools.ietf.org/html/rfc5656)
* [RFC 5915 - Elliptic Curve Private Key Structure](https://tools.ietf.org/html/rfc5915)
* [RFC 5958 - EncryptedPrivateKeyInfo](https://www.rfc-editor.org/rfc/rfc5958)
* [RFC 6668 - SHA-2 Data Integrity Verification for the Secure Shell (SSH) Transport Layer Protocol](https://tools.ietf.org/html/rfc6668)
* [RFC 8160 - IUTF8 Terminal Mode in Secure Shell (SSH)](https://tools.ietf.org/html/rfc8160)
* [RFC 8268 - More Modular Exponentiation (MODP) Diffie-Hellman (DH) Key Exchange (KEX) Groups for Secure Shell (SSH)](https://tools.ietf.org/html/rfc8268)
* [RFC 8308 - Extension Negotiation in the Secure Shell (SSH) Protocol](https://tools.ietf.org/html/rfc8308)
    * **Note:** - the code contains [**hooks**](./event-listeners.md#kexextensionhandler) for implementing the RFC and
    also provides default client and server implementation for `server-sig-algs` extensions.
* [RFC 8332 - Use of RSA Keys with SHA-256 and SHA-512 in the Secure Shell (SSH) Protocol](https://tools.ietf.org/html/rfc8332)
    * **Note:** - the server side supports these signatures by default. The client side requires specific
    initialization - see [section 3.3](https://tools.ietf.org/html/rfc8332#section-3.3) and also the
    above mentioned hooks for [RFC 8308](https://tools.ietf.org/html/rfc8308).
* [RFC 8731 - Secure Shell (SSH) Key Exchange Method Using Curve25519 and Curve448](https://tools.ietf.org/html/rfc8731)
* [Key Exchange (KEX) Method Updates and Recommendations for Secure Shell](https://tools.ietf.org/html/draft-ietf-curdle-ssh-kex-sha2-03)
* [Secure Shell (SSH) Key Exchange Method Using Hybrid Streamlined NTRU Prime sntrup761 and X25519 with SHA-512: sntrup761x25519-sha512](https://www.ietf.org/archive/id/draft-josefsson-ntruprime-ssh-02.html)
* [PQ/T Hybrid Key Exchange in SSH](https://datatracker.ietf.org/doc/html/draft-kampanakis-curdle-ssh-pq-ke-04)

### OpenSSH

* [OpenSSH support for U2F/FIDO security keys](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f)
    * **Note:** the server side supports these keys by default. The client side requires specific initialization
* [OpenSSH public-key certificate authentication system for use by SSH](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys)
* [OpenSSH 1.9 transport: strict key exchange extension](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL)
* [(Some) OpenSSH SFTP extensions](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL)

**Note:** some implementations may be limited to client-side - i.e., we provide a capability for the client to detect if the server
supports the extension and then use it, but our server does not publish it as being supported.

| Section | Extension                  | Client | Server |
| ------- | -------------------------- | ------ | ------ |
| 4.3     | `posix-rename@openssh.com` | Yes    | Yes    |
| 4.4     | `statvfs@openssh.com`      | Yes    | Yes    |
| 4.4     | `fstatvfs@openssh.com`     | Yes    | Yes    |
| 4.5     | `hardlink@openssh.com`     | Yes    | Yes    |
| 4.6     | `fsync@openssh.com`        | Yes    | Yes    |
| 4.7     | `lsetstat@openssh.com`     | Yes    | Yes    |
| 4.8     | `limits@openssh.com`       | Yes    | Yes    |
| 4.10    | `copy-data`                | Yes    | Yes    |

### SFTP version 3-6 + extensions

* `supported` - [DRAFT 05 - section 4.4](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-05#section-4.4)
* `supported2` - [DRAFT 13 section 5.4](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-13#section-5.4)
* `versions` - [DRAFT 09 Section 4.6](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-09#section-4.6)
* `vendor-id` - [DRAFT 09 - section 4.4](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-09#section-4.4)
* `acl-supported` - [DRAFT 11 - section 5.4](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-11#section-5.4)
* `newline` - [DRAFT 09 Section 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-09#section-4.3)
* `md5-hash`, `md5-hash-handle` - [DRAFT 09 - section 9.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-09#section-9.1.1)
* `check-file-handle`, `check-file-name` - [DRAFT 09 - section 9.1.2](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-09#section-9.1.2)
* `copy-file`, `copy-data` - [DRAFT 00 - sections 6, 7](https://tools.ietf.org/id/draft-ietf-secsh-filexfer-extensions-00.txt)
* `space-available` - [DRAFT 09 - section 9.2](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-09#section-9.2)
* `filename-charset`, `filename-translation-control` - [DRAFT 13 - section 6](https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-6) - only client side

### Miscellaneous

* [SSH proxy jumps](./internals.md#ssh-jumps)
* [Endless tarpit](https://nullprogram.com/blog/2019/03/22/) - see [HOWTO(s)](./howto.md) section.

## Implemented/available support

### Authentication methods

* hostbased, publickey, [OpenSSH host-based public-key](https://github.com/openssh/openssh-portable/blob/1781f507c11/PROTOCOL#L349), keyboard-interactive, password

### Ciphers

* aes128-cbc, aes128-ctr, aes192-cbc, aes192-ctr, aes256-cbc, aes256-ctr, arcfour128, arcfour256, blowfish-cbc,
aes128-gcm@<!-- -->openssh.com, aes256-gcm@<!-- -->openssh.com, chacha20-poly1305@<!-- -->openssh.com, 3des-cbc

### Digests

* md5, sha1, sha224, sha256, sha384, sha512

### Macs

* hmacmd5, hmacmd596, hmacsha1, hmacsha196, hmacsha256, hmacsha512, hmac-sha2-256-etm@<!-- -->openssh.com
, hmac-sha2-512-etm@<!-- -->openssh.com, hmac-sha1-etm@<!-- -->openssh.com

### Key exchange

* diffie-hellman-group1-sha1, diffie-hellman-group-exchange-sha256, diffie-hellman-group14-sha1, diffie-hellman-group14-sha256
, diffie-hellman-group15-sha512, diffie-hellman-group16-sha512, diffie-hellman-group17-sha512, diffie-hellman-group18-sha512
, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521, curve25519-sha256, curve25519-sha256@<!-- -->libssh.org, curve448-sha512
    * On Java versions before Java 11, [Bouncy Castle](./dependencies.md#bouncy-castle) is required for curve25519-sha256, curve25519-sha256@<!-- -->libssh.org, or curve448-sha512.

* If [Bouncy Castle](./dependencies.md#bouncy-castle) is present, the following post-quantum cryptography (PQC) hybrid key exchanges are also supported: sntrup761x25519-sha512, sntrup761x25519-sha512@<!-- -->openssh.com, mlkem768x25519-sha256, mlkem768nistp256-sha256, and
mlkem1024nistp384-sha384.

### Compressions

* none, zlib, zlib@<!-- -->openssh.com

### Signatures/Keys

* ssh-dss, ssh-rsa, rsa-sha2-256, rsa-sha2-512, nistp256, nistp384, nistp521
, ssh-ed25519 (requires Bouncy Castle or `net.i2p.crypto.eddsa` as an optional dependency - if both are present, `net.i2p.crypto.eddsa` is used)
, sk-ecdsa-sha2-nistp256@<!-- -->openssh.com, sk-ssh-ed25519@<!-- -->openssh.com
, ssh-rsa-cert-v01@<!-- -->openssh.com, ssh-dss-cert-v01<!-- -->@openssh.com, ssh-ed25519-cert-v01@<!-- -->openssh.com
, ecdsa-sha2-nistp256-cert-v01@<!-- -->openssh.com, ecdsa-sha2-nistp384-cert-v01<!-- -->@openssh.com
, ecdsa-sha2-nistp521-cert-v01<!-- -->@openssh.com

**Note:** The above list contains all the supported security settings in the code. However, in accordance with the latest recommendations
the default client/server setup includes only the security settings that are currently considered safe to use. Users who wish to include
the unsafe settings must do so **explicitly**. The following settings have been deprecated and are no longer included in the default setup:

* [RFC 8758 - Deprecating RC4 in Secure Shell (SSH)](https://tools.ietf.org/html/rfc8758)
* [RFC 8429 - Deprecate Triple-DES (3DES) and RC4 in Kerberos](https://tools.ietf.org/html/rfc8429)
    * While it refers to Kerberos, it mentions weaknesses in DES as well.
* [OpenSSH release notes](https://www.openssh.com/releasenotes.html) - usually a good indicator of de-facto practices
* SHA-1 based key exchanges and signatures
* MD5-based and truncated HMAC algorithms
* Ciphers using CBC mode.
* [RFC 8270 - Increase the Secure Shell Minimum Recommended Diffie-Hellman Modulus Size to 2048 Bits](https://tools.ietf.org/html/rfc8270)
    **Note:** it still possible to use 1024 by initializing the value *programmatically* or via system property -
    see [Security providers setup](./security-providers.md#diff-hellman-group-exchange-configuration).
    The code still contains moduli for 1024 and will use them if user **explicitly** lowers the default minimum
    to it.

**Caveat:**: According to [RFC 8332 - section 3.31](https://tools.ietf.org/html/rfc8332#section-3.3)
>>
>> Implementation experience has shown that there are servers that apply authentication penalties to clients
>> attempting public key algorithms that the SSH server does not support.
>>
>> When authenticating with an RSA key against a server that does not implement the "server-sig-algs" extension,
>> clients MAY default to an "ssh-rsa" signature to avoid authentication penalties. When the new rsa-sha2-*
>> algorithms have been sufficiently widely adopted to warrant disabling "ssh-rsa", clients MAY default to one of
>> the new algorithms.

This means that users that encounter this (and related) problems must modify the supported security settings
**explicitly** in order to avoid the issue.

**Special notice:** `ssh-rsa` was left in as part of the default setup since there are still a lot of systems / users
using it. However, in future version it will be removed from the default. We therefore strongly encourage users to migrate
to other keys (e.g. ECDSA, ED25519) as soon as possible.
