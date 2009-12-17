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
package org.apache.sshd.server;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.server.session.ServerSession;

import java.net.InetSocketAddress;

/**
 * Determines if a forwarding request will be permitted.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ForwardingFilter {
    /**
     * Determine if the session may arrange for agent forwarding.
     * <p>
     * This server process will open a new listen socket locally and export
     * the address in the {@link SshAgent#SSH_AUTHSOCKET_ENV_NAME} environment
     * variable.
     *
     * @param session session requesting permission to forward the agent.
     * @return true if the agent forwarding is permitted, false if denied.
     */
    boolean canForwardAgent(ServerSession session);

    /**
     * Determine if the session may arrange for X11 forwarding.
     * <p>
     * This server process will open a new listen socket locally and export
     * the address in the environment so X11 clients can be tunneled to the
     * user's X11 display server.
     *
     * @param session session requesting permission to forward X11 connections.
     * @return true if the X11 forwarding is permitted, false if denied.
     */
    boolean canForwardX11(ServerSession session);

    /**
     * Determine if the session may listen for inbound connections.
     * <p>
     * This server process will open a new listen socket on the address given
     * by the client (usually 127.0.0.1 but may be any address).  Any inbound
     * connections to this socket will be tunneled over the session to the
     * client, which the client will then forward the connection to another
     * host on the client's side of the network.
     *
     * @param address address the client has requested this server listen
     *  for inbound connections on, and relay them through the client.
     * @param session session requesting permission to listen for connections.
     * @return true if the socket is permitted; false if it must be denied.
     */
    boolean canListen(InetSocketAddress address, ServerSession session);

    /**
     * Determine if the session may create an outbound connection.
     * <p>
     * This server process will connect to another server listening on the
     * address specified by the client.  Usually this is to another port on
     * the same host (127.0.0.1) but may be to any other system this server
     * can reach on the server's side of the network.
     *
     * @param address address the client has requested this server listen
     *  for inbound connections on, and relay them through the client.
     * @param session session requesting permission to listen for connections.
     * @return true if the socket is permitted; false if it must be denied.
     */
    boolean canConnect(InetSocketAddress address, ServerSession session);
}
