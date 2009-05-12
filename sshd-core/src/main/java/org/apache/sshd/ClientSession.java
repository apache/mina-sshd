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
package org.apache.sshd;

import java.io.IOException;
import java.security.PublicKey;

import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.common.future.CloseFuture;

/**
 * An authenticated session to a given SSH server
 *
 * A client session is established using the {@link SshClient}.
 * Once the session has been created, the user has to authenticate
 * using either {@link #authPassword(String, String)} or
 * {@link #authPublicKey(String, java.security.PublicKey)}.
 *
 * From this session, channels can be created using the
 * {@link #createChannel(String)} method.  Multiple channels can
 * be created on a given session concurrently.
 *
 * When using the client in an interactive mode, the
 * {@link #waitFor(int, long)} method can be used to listen to specific
 * events such as the session being established, authenticated or closed.
 *
 * When a given session is no longer used, it must be closed using the
 * {@link #close(boolean)} method.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ClientSession {

    int TIMEOUT =     0x0001;
    int CLOSED =      0x0002;
    int WAIT_AUTH =   0x0004;
    int AUTHED =      0x0008;

    AuthFuture authPassword(String username, String password) throws IOException;

    AuthFuture authPublicKey(String username, PublicKey key) throws IOException;

    ClientChannel createChannel(String type) throws Exception;

    int waitFor(int mask, long timeout);

    CloseFuture close(boolean immediately);

}
