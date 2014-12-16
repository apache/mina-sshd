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
import java.security.KeyPair;
import java.util.Map;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.ScpClient;
import org.apache.sshd.client.SftpClient;
import org.apache.sshd.client.UserInteraction;
import org.apache.sshd.client.channel.ChannelDirectTcpip;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ChannelSubsystem;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFuture;

/**
 * An authenticated session to a given SSH server
 *
 * A client session is established using the {@link SshClient}.
 * Once the session has been created, the user has to authenticate
 * using either {@link #authPassword(String, String)} or
 * {@link #authPublicKey(String, java.security.KeyPair)}.
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
public interface ClientSession extends Session {

    int TIMEOUT =     0x0001;
    int CLOSED =      0x0002;
    int WAIT_AUTH =   0x0004;
    int AUTHED =      0x0008;

    void addPasswordIdentity(String password);
    void addPublicKeyIdentity(KeyPair key);

    UserInteraction getUserInteraction();
    void setUserInteraction(UserInteraction userInteraction);

    /**
     * Starts the authentication process.
     * User identities will be tried until the server successfully authenticate the user.
     * User identities must be provided before calling this method using
     * {@link #addPasswordIdentity(String)} or {@link #addPublicKeyIdentity(java.security.KeyPair)}.
     *
     * @return the authentication future
     * @throws IOException
     * @see #addPasswordIdentity(String)
     * @see #addPublicKeyIdentity(java.security.KeyPair)
     */
    AuthFuture auth() throws IOException;

    /**
     * Authenticate the session with the given username using an ssh agent.
     *
     * @deprecated Use {@link #auth()} instead
     * @see #auth()
     */
    @Deprecated
    AuthFuture authAgent(String username) throws IOException;

    /**
     * Authenticate the session with the given username and password.
     *
     * @deprecated Use {@link #auth()} instead
     * @see #auth()
     */
    @Deprecated
    AuthFuture authPassword(String username, String password) throws IOException;

    /**
     * Authenticate the session with the given username and password.
     *
     * @deprecated Use {@link #auth()} instead
     * @see #auth()
     */
    @Deprecated
    AuthFuture authInteractive(String username, String password) throws IOException;

    /**
     * Authenticate the session with the given username and public key.
     *
     * @deprecated Use {@link #auth()} instead
     * @see #auth()
     */
    @Deprecated
    AuthFuture authPublicKey(String username, KeyPair key) throws IOException;

    /**
     * Create a channel of the given type.
     * Same as calling <code>createChannel(type, null)</code>.
     */
    ClientChannel createChannel(String type) throws IOException;

    /**
     * Create a channel of the given type and subtype.
     */
    ClientChannel createChannel(String type, String subType) throws IOException;

    /**
     * Create a channel to start a shell.
     */
    ChannelShell createShellChannel() throws IOException;

    /**
     * Create a channel to execute a command.
     */
    ChannelExec createExecChannel(String command) throws IOException;

    /**
     * Create a subsystem channel.
     */
    ChannelSubsystem createSubsystemChannel(String subsystem) throws IOException;

    /**
     * Create a direct tcp-ip channel which can be used to stream data to a remote port from the server.
     */
    ChannelDirectTcpip createDirectTcpipChannel(SshdSocketAddress local, SshdSocketAddress remote) throws IOException;

    /**
     * Create an SCP client from this session.
     */
    ScpClient createScpClient();

    /**
     * Create an SFTP client from this session.
     */
    SftpClient createSftpClient() throws IOException;

    /**
     * Start forwarding the given local address on the client to the given address on the server.
     */
    SshdSocketAddress startLocalPortForwarding(SshdSocketAddress local, SshdSocketAddress remote) throws IOException;

    /**
     * Stop forwarding the given local address.
     */
    void stopLocalPortForwarding(SshdSocketAddress local) throws IOException;

    /**
     * Start forwarding tcpip from the given address on the server to the
     * given address on the client.
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
     * Start dynamic local port forwarding using a SOCKS proxy.
     *
     * @param local
     * @return
     * @throws IOException
     */
    SshdSocketAddress startDynamicPortForwarding(SshdSocketAddress local) throws IOException;

    /**
     * Stop a previously started dynamic port forwarding.
     *
     * @param local
     * @throws IOException
     */
    void stopDynamicPortForwarding(SshdSocketAddress local) throws IOException;

    /**
     * Wait for a specific state.
     */
    int waitFor(int mask, long timeout);

    /**
     * Close this session.
     */
    CloseFuture close(boolean immediately);

    /**
     * Access to the metadata.
     */
    Map<Object, Object> getMetadataMap();

    /**
     * Return ClientFactoryManager for this session.
     */
    ClientFactoryManager getFactoryManager();

    /**
     * Switch to a none cipher for performance.
     *
     * This should be done after the authentication phase has been performed.
     * After such a switch, interactive channels are not allowed anymore.
     * Both client and server must have been configured to support the none cipher.
     * If that's not the case, the returned future will be set with an exception.
     *
     * @return an {@link SshFuture} that can be used to wait for the exchange
     *         to be finished
     * @throws IOException if a key exchange is already running
     */
    SshFuture switchToNoneCipher() throws IOException;

}
