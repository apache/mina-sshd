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

import org.apache.sshd.client.config.hosts.KnownHostEntry;
import org.apache.sshd.client.session.ClientSession;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface ModifiedServerKeyAcceptor {
    /**
     * Invoked when a matching known host key was found but it does not match the presented one.
     *
     * @param  clientSession The {@link ClientSession}
     * @param  remoteAddress The remote host address
     * @param  entry         The original {@link KnownHostEntry} whose key did not match
     * @param  expected      The expected server {@link PublicKey}
     * @param  actual        The presented server {@link PublicKey}
     * @return               {@code true} if accept the server key anyway
     * @throws Exception     if cannot process the request - equivalent to {@code false} return value
     */
    boolean acceptModifiedServerKey(
            ClientSession clientSession, SocketAddress remoteAddress,
            KnownHostEntry entry, PublicKey expected, PublicKey actual)
            throws Exception;
}
