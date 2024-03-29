/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.client.future;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionHolder;
import org.apache.sshd.common.future.Cancellable;
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.future.VerifiableFuture;
import org.apache.sshd.common.session.SessionHolder;

/**
 * An {@link SshFuture} for asynchronous connections requests.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ConnectFuture
        extends SshFuture<ConnectFuture>,
        VerifiableFuture<ConnectFuture>,
        SessionHolder<ClientSession>,
        ClientSessionHolder, Cancellable {

    @Override
    default ClientSession getClientSession() {
        return getSession();
    }

    /**
     * @return <code>true</code> if the connect operation is finished successfully.
     */
    boolean isConnected();

    /**
     * Sets the newly connected session and notifies all threads waiting for this future. This method is invoked by SSHD
     * internally. Please do not call this method directly.
     *
     * @param session The {@link ClientSession}
     */
    void setSession(ClientSession session);

}
