/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

Welcome to Apache SSHD

Apache SSHD is a library to support the SSH2 protocol on both
client and server side using pure Java.

This distribution provides a simple demonstration of a SSH
server and client that you can launched using the shell scripts in the
bin folder. By default, the port used is 8000 and the authentication
will succeed if the username and password are the same.
SCP and SFTP support are both enabled by default in this configuration.

The artifacts are distributed as follows:

* /bin - contains Linux and Windows scripts that can be used to run
  the code using the default settings.

* /lib - contains all the JAR(s) necessary to run both SSH client and
  server - including the various supported I/O factories (default is
  the built-in NIO2), SCP, SFTP, SOCKS, ed25519 support.

* /extras - contains various SSH-based or SSH-related extra functionality
  that is not part of SSH per-se. E.g., JGit, Putty, LDAP, Spring SFTP,
  various contributions.

* /dependencies - contains various required 3rd party artifacts that are
  used by the extra(s).

* /licenses - contains a copy of all the 3rd party artifacts' licenses
  that are used by this project

Please send feedback to users@mina.apache.org.

The Apache SSHD team.