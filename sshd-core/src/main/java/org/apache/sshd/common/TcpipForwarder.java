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
package org.apache.sshd.common;


import java.io.IOException;

public interface TcpipForwarder extends Closeable {

    /**
     * Start forwarding the given local address on the client to the given address on the server.
     */
    SshdSocketAddress startLocalPortForwarding(SshdSocketAddress local, SshdSocketAddress remote) throws IOException;

    /**
     * Stop forwarding the given local address.
     */
    void stopLocalPortForwarding(SshdSocketAddress local) throws IOException;

    /**
     * Start forwarding tcpip from the given remote address to the
     * given local address.
     *
     * The remote host name is the address to bind to on the server:
     * <ul>
     *    <li>"" means that connections are to be accepted on all protocol families
     *              supported by the SSH implementation</li>
     *    <li>"0.0.0.0" means to listen on all IPv4 addresses</li>
     *    <li>"::" means to listen on all IPv6 addresses</li>
     *    <li>"localhost" means to listen on all protocol families supported by the SSH
     *              implementation on loopback addresses only, [RFC3330] and RFC3513]</li>
     *    <li>"127.0.0.1" and "::1" indicate listening on the loopback interfaces for
     *              IPv4 and IPv6 respectively</li>
     * </ul>
     *
     */
    SshdSocketAddress startRemotePortForwarding(SshdSocketAddress remote, SshdSocketAddress local) throws IOException;

    /**
     * Stop forwarding of the given remote address.
     */
    void stopRemotePortForwarding(SshdSocketAddress remote) throws IOException;

    /**
     * Retrieve the local address that the remote port is forwarded to
     * @param remotePort
     * @return
     */
    SshdSocketAddress getForwardedPort(int remotePort);

    /**
     * Called when the other side requested a remote port forward.
     * @param local
     * @return the list of bound local addresses
     * @throws IOException
     */
    SshdSocketAddress localPortForwardingRequested(SshdSocketAddress local) throws IOException;

    /**
     * Called when the other side cancelled a remote port forward.
     * @param local
     * @throws IOException
     */
    void localPortForwardingCancelled(SshdSocketAddress local) throws IOException;

    /**
     * Close the forwarder
     */
    @Deprecated
    void close();

    SshdSocketAddress startDynamicPortForwarding(SshdSocketAddress local) throws IOException;

    void stopDynamicPortForwarding(SshdSocketAddress local) throws IOException;

}
