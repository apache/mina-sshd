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

import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.SshdEventListener;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PortForwardingEventListener extends SshdEventListener {
    PortForwardingEventListener EMPTY = new PortForwardingEventListener() {
        @Override
        public String toString() {
            return "EMPTY";
        }
    };

    /**
     * Signals the attempt to establish a local/remote port forwarding
     *
     * @param  session         The {@link Session} through which the attempt is made
     * @param  local           The local address - may be {@code null} on the receiver side
     * @param  remote          The remote address - may be {@code null} on the receiver side
     * @param  localForwarding Local/remote port forwarding indicator
     * @throws IOException     If failed to handle the event - in which case the attempt is aborted and the exception
     *                         re-thrown to the caller
     */
    default void establishingExplicitTunnel(
            Session session, SshdSocketAddress local, SshdSocketAddress remote, boolean localForwarding)
            throws IOException {
        // ignored
    }

    /**
     * Signals a successful/failed attempt to establish a local/remote port forwarding
     *
     * @param  session         The {@link Session} through which the attempt was made
     * @param  local           The local address - may be {@code null} on the receiver side
     * @param  remote          The remote address - may be {@code null} on the receiver side
     * @param  localForwarding Local/remote port forwarding indicator
     * @param  boundAddress    The bound address - non-{@code null} if successful
     * @param  reason          Reason for failure - {@code null} if successful
     * @throws IOException     If failed to handle the event - in which case the established tunnel is aborted
     */
    default void establishedExplicitTunnel(
            Session session, SshdSocketAddress local, SshdSocketAddress remote, boolean localForwarding,
            SshdSocketAddress boundAddress, Throwable reason)
            throws IOException {
        // ignored
    }

    /**
     * Signals a request to tear down a local/remote port forwarding
     *
     * @param  session         The {@link Session} through which the request is made
     * @param  address         The (bound) address - local/remote according to the forwarding type
     * @param  localForwarding Local/remote port forwarding indicator
     * @param  remoteAddress   The specified peer address when tunnel was established - may be {@code null} for
     *                         server-side local tunneling requests
     * @throws IOException     If failed to handle the event - in which case the request is aborted
     */
    default void tearingDownExplicitTunnel(
            Session session, SshdSocketAddress address, boolean localForwarding, SshdSocketAddress remoteAddress)
            throws IOException {
        // ignored
    }

    /**
     * Signals a successful/failed request to tear down a local/remote port forwarding
     *
     * @param  session         The {@link Session} through which the request is made
     * @param  address         The (bound) address - local/remote according to the forwarding type
     * @param  localForwarding Local/remote port forwarding indicator
     * @param  remoteAddress   The specified peer address when tunnel was established - may be {@code null} for
     *                         server-side local tunneling requests
     * @param  reason          Reason for failure - {@code null} if successful
     * @throws IOException     If failed to handle the event - <B>Note:</B> the exception is propagated, but the port
     *                         forwarding may have been torn down - no rollback
     */
    default void tornDownExplicitTunnel(
            Session session, SshdSocketAddress address, boolean localForwarding, SshdSocketAddress remoteAddress,
            Throwable reason)
            throws IOException {
        // ignored
    }

    /**
     * Signals the attempt to establish a dynamic port forwarding
     *
     * @param  session     The {@link Session} through which the attempt is made
     * @param  local       The local address
     * @throws IOException If failed to handle the event - in which case the attempt is aborted and the exception
     *                     re-thrown to the caller
     */
    default void establishingDynamicTunnel(Session session, SshdSocketAddress local) throws IOException {
        // ignored
    }

    /**
     * Signals a successful/failed attempt to establish a dynamic port forwarding
     *
     * @param  session      The {@link Session} through which the attempt is made
     * @param  local        The local address
     * @param  boundAddress The bound address - non-{@code null} if successful
     * @param  reason       Reason for failure - {@code null} if successful
     * @throws IOException  If failed to handle the event - in which case the established tunnel is aborted
     */
    default void establishedDynamicTunnel(
            Session session, SshdSocketAddress local, SshdSocketAddress boundAddress, Throwable reason)
            throws IOException {
        // ignored
    }

    /**
     * Signals a request to tear down a dynamic forwarding
     *
     * @param  session     The {@link Session} through which the request is made
     * @param  address     The (bound) address - local/remote according to the forwarding type
     * @throws IOException If failed to handle the event - in which case the request is aborted
     */
    default void tearingDownDynamicTunnel(Session session, SshdSocketAddress address) throws IOException {
        // ignored
    }

    /**
     * Signals a successful/failed request to tear down a dynamic port forwarding
     *
     * @param  session     The {@link Session} through which the request is made
     * @param  address     The (bound) address - local/remote according to the forwarding type
     * @param  reason      Reason for failure - {@code null} if successful
     * @throws IOException If failed to handle the event - <B>Note:</B> the exception is propagated, but the port
     *                     forwarding may have been torn down - no rollback
     */
    default void tornDownDynamicTunnel(Session session, SshdSocketAddress address, Throwable reason) throws IOException {
        // ignored
    }

    static <L extends PortForwardingEventListener> L validateListener(L listener) {
        return SshdEventListener.validateListener(listener, PortForwardingEventListener.class.getSimpleName());
    }
}
