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

package org.apache.sshd.client.session;

import org.apache.sshd.core.CoreModuleProperties;

/**
 * Provides a way to implement proxied connections where some metadata about the client is sent <U>before</U> the actual
 * SSH protocol is executed - e.g., the <A HREF=@http://www.haproxy.org/download/1.6/doc/proxy-protocol.txt">PROXY
 * protocol</A>. The implementor should use the {@code IoSession#write(Buffer)} method to send any packets with the
 * meta-data.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface ClientProxyConnector {
    /**
     * Invoked once initial connection has been established so that the proxy can open its channel and send the
     * meta-data to its peer. Upon successful return the SSH identification line is eventually sent and the protocol
     * proceeds as usual.
     *
     * @param  session   The {@link ClientSession} instance - <B>Note:</B> at this stage the client's identification
     *                   line is not set yet.
     * @throws Exception If failed to initialize the proxy - which will also terminate the session
     * @see              CoreModuleProperties#SEND_IMMEDIATE_IDENTIFICATION SEND_IMMEDIATE_IDENTIFICATION
     */
    void sendClientProxyMetadata(ClientSession session) throws Exception;
}
