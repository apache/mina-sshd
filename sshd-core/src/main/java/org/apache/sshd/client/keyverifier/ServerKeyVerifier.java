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
package org.apache.sshd.client.keyverifier;

import java.net.SocketAddress;
import java.security.PublicKey;

import org.apache.sshd.client.session.ClientSession;

/**
 * The <code>ServerKeyVerifier</code> is used on the client side to authenticate the key provided by the server.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface ServerKeyVerifier {
    /**
     * Verify that the server key provided is really the one of the host.
     *
     * @param  clientSession the current {@link ClientSession}
     * @param  remoteAddress the host's {@link SocketAddress}
     * @param  serverKey     the presented server {@link PublicKey}
     * @return               <code>true</code> if the key is accepted for the host
     */
    boolean verifyServerKey(ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey);
}
