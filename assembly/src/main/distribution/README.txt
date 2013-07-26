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
client and server side in java.

This distribution provides a simple demonstration of a SSH
server that you can launched using the shell scripts in the
bin folder.  By default, the port used is 8000 and the authentication
will succeed if the username and password are the same.
SCP and SFTP support are both enabled in this configuration.

The lib folder contains the sshd-core jar which is the main jar
and its required dependencies (slf4j-api and mina-core).
Note that if you're running on JDK 7, mina-core becomes an optional
dependency as a native IO layer built on top of NIO2 is provided
and selected by default if available.

The sshd-pam module is an experimental module for leveraging the
Unix PAM authentication mechanism which is not really usable at the
moment.
The sshf-sftp module is an experimental module which provides an
object model for the SFTP subsystem to ease writing custom SFTP
servers.

Please send feedback to users@mina.apache.org.

The Apache SSHD team.