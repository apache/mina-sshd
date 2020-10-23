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

package org.apache.sshd.common.forward;

import java.io.IOException;

import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PortForwardingManager extends PortForwardingInformationProvider {
    /**
     * Start forwarding the given local port on the client to the given address on the server.
     *
     * @param  localPort   The local port - if zero then one will be allocated
     * @param  remote      The remote address
     * @return             The bound {@link SshdSocketAddress}
     * @throws IOException If failed to create the requested binding
     */
    default SshdSocketAddress startLocalPortForwarding(int localPort, SshdSocketAddress remote) throws IOException {
        return startLocalPortForwarding(new SshdSocketAddress(localPort), remote);
    }

    /**
     * Start forwarding the given local address on the client to the given address on the server.
     *
     * @param  local       The local address
     * @param  remote      The remote address
     * @return             The bound {@link SshdSocketAddress}
     * @throws IOException If failed to create the requested binding
     */
    SshdSocketAddress startLocalPortForwarding(SshdSocketAddress local, SshdSocketAddress remote) throws IOException;

    /**
     * Stop forwarding the given local address.
     *
     * @param  local       The local address
     * @throws IOException If failed to cancel the requested binding
     */
    void stopLocalPortForwarding(SshdSocketAddress local) throws IOException;

    /**
     * <P>
     * Start forwarding tcpip from the given address on the server to the given address on the client.
     * </P>
     * The remote host name is the address to bind to on the server:
     * <ul>
     * <li>"" means that connections are to be accepted on all protocol families supported by the SSH
     * implementation</li>
     * <li>"0.0.0.0" means to listen on all IPv4 addresses</li>
     * <li>"::" means to listen on all IPv6 addresses</li>
     * <li>"localhost" means to listen on all protocol families supported by the SSH implementation on loopback
     * addresses only, [RFC3330] and RFC3513]</li>
     * <li>"127.0.0.1" and "::1" indicate listening on the loopback interfaces for IPv4 and IPv6 respectively</li>
     * </ul>
     *
     * @param  local       The local address
     * @param  remote      The remote address
     * @return             The bound {@link SshdSocketAddress}
     * @throws IOException If failed to create the requested binding
     */
    SshdSocketAddress startRemotePortForwarding(SshdSocketAddress remote, SshdSocketAddress local) throws IOException;

    /**
     * Stop forwarding of the given remote address.
     *
     * @param  remote      The remote address
     * @throws IOException If failed to cancel the requested binding
     */
    void stopRemotePortForwarding(SshdSocketAddress remote) throws IOException;

    /**
     * Start dynamic local port forwarding using a SOCKS proxy.
     *
     * @param  local       The local address
     * @return             The bound {@link SshdSocketAddress}
     * @throws IOException If failed to create the requested binding
     */
    SshdSocketAddress startDynamicPortForwarding(SshdSocketAddress local) throws IOException;

    /**
     * Stop a previously started dynamic port forwarding.
     *
     * @param  local       The local address
     * @throws IOException If failed to cancel the requested binding
     */
    void stopDynamicPortForwarding(SshdSocketAddress local) throws IOException;
}
