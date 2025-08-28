<!--
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements. See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to You under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License. You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->
# Apache MINA sshd

Welcome to the _development_ web site of Apache MINA sshd. This web site currently
contains technical information about the development of a new major release **3.0.0**.

Apache MINA sshd is a pure Java library for client- and server-side SSH.

* The main web site is at [Apache MINA sshd](https://mina.apache.org/sshd-project).
* For now, [technical documentation](https://github.com/apache/mina-sshd/blob/master/README.md)
still lives directly in the git repository and can be viewed as rendered web pages in GitHub.
* Technical information on the development of release 3.0.0 is available in branch `dev_3.0`:
    * [Changes since 2.16.0](https://github.com/apache/mina-sshd/blob/dev_3.0/CHANGES.md)
    * [Technical documentation](https://github.com/apache/mina-sshd/tree/dev_3.0/docs/technical)

Release 3.0.0 will be a new major release and will contain many breaking API changes.
It will not be API-compatible with the 2.X releases. There are
[`japicmp`](https://siom79.github.io/japicmp) reports about the API changes available
here; see the menu on the left. Most of the API changes affect only the `protected` API,
i.e., the API for subclassing. But there are also changes in the `public` API that may
affect user code.

## Roadmap

We cannot give a definitive roadmap with milestone dates. All development is done by
volunteers in their free time and resources are limited.

But we can give you a rough outline of what we want to do:

* **3.0.0-M1**: Rework of the SSH transport protocol as a filter chain. The main user-visible new feature is support for client-side proxies.

Further possible milestones (the order might change, though):

* Some rework of handling of private/public keys. No new feature planned, it's necessary clean-up that will require some public API changes.
* Resolve the split packages between `sshd-common` and `sshd-core`.
* Support Java native ed25519 on Java >= 15. This may result in a multi-release JAR artifact.
* Some refactoring of SFTP code; current code has shortcomings regarding SFTP file systems.
* Anything else we stumble upon and that we cannot fix reasonably without breaking API.

We reserve the right to make arbitrary API changes between M-releases.