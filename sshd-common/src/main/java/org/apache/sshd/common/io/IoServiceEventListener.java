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

package org.apache.sshd.common.io;

import java.io.IOException;
import java.net.SocketAddress;

import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.util.SshdEventListener;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface IoServiceEventListener extends SshdEventListener {
    /**
     * Called when a new connection has been created to a remote peer - <u>before</u> it was converted into a session
     *
     * @param  connector   The {@link IoConnector} through which the connection was established
     * @param  local       The local connection endpoint
     * @param  context     An optional &quot;context&quot; provided by the user when connection was requested
     * @param  remote      The remote connection endpoint
     * @throws IOException If failed to handle the event - in which case connection will be aborted
     */
    default void connectionEstablished(
            IoConnector connector, SocketAddress local, AttributeRepository context, SocketAddress remote)
            throws IOException {
        // Do nothing
    }

    /**
     * Called when a previously established connection has been abnormally terminated before it could be turned into a
     * session
     *
     * @param  connector   The {@link IoConnector} through which the connection was established
     * @param  local       The local connection endpoint
     * @param  context     An optional &quot;context&quot; provided by the user when connection was requested
     * @param  remote      The remote connection endpoint
     * @param  reason      The reason for aborting - may be an exception thrown by
     *                     {@link #connectionEstablished(IoConnector, SocketAddress, AttributeRepository, SocketAddress)
     *                     connectionEstablished}
     * @throws IOException If failed to handle the event - the exception is logged but does not prevent further
     *                     connections from being accepted
     */
    default void abortEstablishedConnection(
            IoConnector connector, SocketAddress local, AttributeRepository context, SocketAddress remote, Throwable reason)
            throws IOException {
        // Do nothing
    }

    /**
     * Called when a new connection has been accepted from a remote peer - <u>before</u> it was converted into a session
     *
     * @param  acceptor    The {@link IoAcceptor} through which the connection was accepted
     * @param  local       The local connection endpoint
     * @param  remote      The remote connection endpoint
     * @param  service     The service listen endpoint through which the connection was accepted
     * @throws IOException If failed to handle the event - in which case connection will be aborted
     */
    default void connectionAccepted(
            IoAcceptor acceptor, SocketAddress local, SocketAddress remote, SocketAddress service)
            throws IOException {
        // Do nothing
    }

    /**
     * Called when a previously accepted connection has been abnormally terminated before it could be turned into a
     * session
     *
     * @param  acceptor    The {@link IoAcceptor} through which the connection was accepted
     * @param  local       The local connection endpoint
     * @param  remote      The remote connection endpoint
     * @param  service     The service listen endpoint through which the connection was accepted
     * @param  reason      The reason for aborting - may be an exception thrown by
     *                     {@link #connectionAccepted(IoAcceptor, SocketAddress, SocketAddress, SocketAddress)
     *                     connectionAccepted}
     * @throws IOException If failed to handle the event - the exception is logged but does not prevent further
     *                     connections from being accepted
     */
    default void abortAcceptedConnection(
            IoAcceptor acceptor, SocketAddress local, SocketAddress remote, SocketAddress service, Throwable reason)
            throws IOException {
        // Do nothing
    }
}
