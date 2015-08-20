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

import java.io.IOException;
import java.nio.file.FileSystem;
import java.security.KeyPair;
import java.util.Map;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.auth.UserInteraction;
import org.apache.sshd.client.channel.ChannelDirectTcpip;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ChannelSubsystem;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.scp.ScpClient;
import org.apache.sshd.client.subsystem.sftp.SftpClient;
import org.apache.sshd.client.subsystem.sftp.SftpVersionSelector;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.scp.ScpTransferEventListener;
import org.apache.sshd.common.session.Session;

/**
 * <P>An authenticated session to a given SSH server</P>
 *
 * <P>
 * A client session is established using the {@link org.apache.sshd.client.SshClient}.
 * Once the session has been created, the user has to authenticate
 * using either {@link #addPasswordIdentity(String)} or
 * {@link #addPublicKeyIdentity(java.security.KeyPair)} followed by
 * a call to {$link #auth()}.
 * </P>
 *
 * <P>
 * From this session, channels can be created using the
 * {@link #createChannel(String)} method.  Multiple channels can
 * be created on a given session concurrently.
 * </P>
 *
 * <P>
 * When using the client in an interactive mode, the
 * {@link #waitFor(int, long)} method can be used to listen to specific
 * events such as the session being established, authenticated or closed.
 * </P>
 *
 * When a given session is no longer used, it must be closed using the
 * {@link #close(boolean)} method.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ClientSession extends Session {

    int TIMEOUT = 0x0001;
    int CLOSED = 0x0002;
    int WAIT_AUTH = 0x0004;
    int AUTHED = 0x0008;

    /**
     * @param password Password to be added - may not be {@code null}/empty
     */
    void addPasswordIdentity(String password);

    /**
     * @param password The password to remove - ignored if {@code null}/empty
     * @return The removed password - same one that was added via
     * {@link #addPasswordIdentity(String)} - or {@code null} if no
     * match found
     */
    String removePasswordIdentity(String password);

    /**
     * @param key The {@link KeyPair} to add - may not be {@code null}
     */
    void addPublicKeyIdentity(KeyPair key);

    /**
     * @param kp The {@link KeyPair} to remove - ignored if {@code null}
     * @return The removed {@link KeyPair} - same one that was added via
     * {@link #addPublicKeyIdentity(KeyPair)} - or {@code null} if no
     * match found
     */
    KeyPair removePublicKeyIdentity(KeyPair kp);

    UserInteraction getUserInteraction();

    void setUserInteraction(UserInteraction userInteraction);

    /**
     * Starts the authentication process.
     * User identities will be tried until the server successfully authenticate the user.
     * User identities must be provided before calling this method using
     * {@link #addPasswordIdentity(String)} or {@link #addPublicKeyIdentity(java.security.KeyPair)}.
     *
     * @return the authentication future
     * @throws IOException if failed to generate the future
     * @see #addPasswordIdentity(String)
     * @see #addPublicKeyIdentity(java.security.KeyPair)
     */
    AuthFuture auth() throws IOException;

    /**
     * Create a channel of the given type.
     * Same as calling <code>createChannel(type, null)</code>.
     *
     * @param type The channel type
     * @return The created {@link ClientChannel}
     * @throws IOException If failed to create the requested channel
     */
    ClientChannel createChannel(String type) throws IOException;

    /**
     * Create a channel of the given type and sub-type.
     *
     * @param type      The channel type
     * @param subType   The channel sub-type
     * @return The created {@link ClientChannel}
     * @throws IOException If failed to create the requested channel
     */
    ClientChannel createChannel(String type, String subType) throws IOException;

    /**
     * Create a channel to start a shell.
     *
     * @return The created {@link ChannelShell}
     * @throws IOException If failed to create the requested channel
     */
    ChannelShell createShellChannel() throws IOException;

    /**
     * Create a channel to execute a command.
     *
     * @param command The command to execute
     * @return The created {@link ChannelExec}
     * @throws IOException If failed to create the requested channel
     */
    ChannelExec createExecChannel(String command) throws IOException;

    /**
     * Create a subsystem channel.
     *
     * @param subsystem The subsystem name
     * @return The created {@link ChannelSubsystem}
     * @throws IOException If failed to create the requested channel
     */
    ChannelSubsystem createSubsystemChannel(String subsystem) throws IOException;

    /**
     * Create a direct tcp-ip channel which can be used to stream data to a remote port from the server.
     *
     * @param local  The local address
     * @param remote The remote address
     * @return The created {@link ChannelDirectTcpip}
     * @throws IOException If failed to create the requested channel
     */
    ChannelDirectTcpip createDirectTcpipChannel(SshdSocketAddress local, SshdSocketAddress remote) throws IOException;

    /**
     * Create an SCP client from this session.
     *
     * @return An {@link ScpClient} instance. <B>Note:</B> uses the currently
     * registered {@link ScpTransferEventListener} if any
     * @see #setScpTransferEventListener(ScpTransferEventListener)
     */
    ScpClient createScpClient();

    /**
     * Create an SCP client from this session.
     *
     * @param listener A {@link ScpTransferEventListener} that can be used
     *                 to receive information about the SCP operations - may be {@code null}
     *                 to indicate no more events are required. <B>Note:</B> this listener
     *                 is used <U>instead</U> of any listener set via {@link #setScpTransferEventListener(ScpTransferEventListener)}
     * @return An {@link ScpClient} instance
     */
    ScpClient createScpClient(ScpTransferEventListener listener);

    /**
     * @return The last {@link ScpTransferEventListener} set via
     * {@link #setScpTransferEventListener(ScpTransferEventListener)}
     */
    ScpTransferEventListener getScpTransferEventListener();

    /**
     * @param listener A default {@link ScpTransferEventListener} that can be used
     *                 to receive information about the SCP operations - may be {@code null}
     *                 to indicate no more events are required
     * @see #createScpClient(ScpTransferEventListener)
     */
    void setScpTransferEventListener(ScpTransferEventListener listener);

    /**
     * Create an SFTP client from this session.
     *
     * @return The created {@link SftpClient}
     * @throws IOException if failed to create the client
     */
    SftpClient createSftpClient() throws IOException;

    /**
     * @param selector The {@link SftpVersionSelector} to use - <B>Note:</B>
     *                 if the server does not support versions re-negotiation then the
     *                 selector will be presented with only one &quot;choice&quot; - the
     *                 current version
     * @return The created {@link SftpClient}
     * @throws IOException If failed to create the client or re-negotiate
     */
    SftpClient createSftpClient(SftpVersionSelector selector) throws IOException;

    FileSystem createSftpFileSystem() throws IOException;

    FileSystem createSftpFileSystem(SftpVersionSelector selector) throws IOException;

    FileSystem createSftpFileSystem(int readBufferSize, int writeBufferSize) throws IOException;

    FileSystem createSftpFileSystem(SftpVersionSelector selector, int readBufferSize, int writeBufferSize) throws IOException;

    /**
     * Start forwarding the given local address on the client to the given address on the server.
     *
     * @param local  The local address
     * @param remote The remote address
     * @return The bound {@link SshdSocketAddress}
     * @throws IOException If failed to create the requested binding
     */
    SshdSocketAddress startLocalPortForwarding(SshdSocketAddress local, SshdSocketAddress remote) throws IOException;

    /**
     * Stop forwarding the given local address.
     *
     * @param local  The local address
     * @throws IOException If failed to cancel the requested binding
     */
    void stopLocalPortForwarding(SshdSocketAddress local) throws IOException;

    /**
     * <P>
     * Start forwarding tcpip from the given address on the server to the
     * given address on the client.
     * </P>
     * The remote host name is the address to bind to on the server:
     * <ul>
     * <li>"" means that connections are to be accepted on all protocol families
     * supported by the SSH implementation</li>
     * <li>"0.0.0.0" means to listen on all IPv4 addresses</li>
     * <li>"::" means to listen on all IPv6 addresses</li>
     * <li>"localhost" means to listen on all protocol families supported by the SSH
     * implementation on loopback addresses only, [RFC3330] and RFC3513]</li>
     * <li>"127.0.0.1" and "::1" indicate listening on the loopback interfaces for
     * IPv4 and IPv6 respectively</li>
     * </ul>
     *
     * @param local  The local address
     * @param remote The remote address
     * @return The bound {@link SshdSocketAddress}
     * @throws IOException If failed to create the requested binding
     */
    SshdSocketAddress startRemotePortForwarding(SshdSocketAddress remote, SshdSocketAddress local) throws IOException;

    /**
     * Stop forwarding of the given remote address.
     *
     * @param remote The remote address
     * @throws IOException If failed to cancel the requested binding
     */
    void stopRemotePortForwarding(SshdSocketAddress remote) throws IOException;

    /**
     * Start dynamic local port forwarding using a SOCKS proxy.
     *
     * @param local The local address
     * @return The bound {@link SshdSocketAddress}
     * @throws IOException If failed to create the requested binding
     */
    SshdSocketAddress startDynamicPortForwarding(SshdSocketAddress local) throws IOException;

    /**
     * Stop a previously started dynamic port forwarding.
     *
     * @param local The local address
     * @throws IOException If failed to cancel the requested binding
     */
    void stopDynamicPortForwarding(SshdSocketAddress local) throws IOException;

    /**
     * Wait for a specific state.
     *
     * @param mask    The request mask
     * @param timeout Wait time in milliseconds - non-positive means forever
     * @return The actual state that was detected either due to the mask
     * yielding non-zero state or due to timeout (in which case the {@link #TIMEOUT}
     * bit is set)
     */
    int waitFor(int mask, long timeout);

    /**
     * Access to the metadata.
     *
     * @return The metadata {@link Map}
     */
    Map<Object, Object> getMetadataMap();

    /**
     * @return The ClientFactoryManager for this session.
     */
    @Override
    ClientFactoryManager getFactoryManager();

    /**
     * <P>Switch to a none cipher for performance.</P>
     *
     * <P>
     * This should be done after the authentication phase has been performed.
     * After such a switch, interactive channels are not allowed anymore.
     * Both client and server must have been configured to support the none cipher.
     * If that's not the case, the returned future will be set with an exception.
     * </P>
     *
     * @return an {@link SshFuture} that can be used to wait for the exchange
     * to be finished
     * @throws IOException if a key exchange is already running
     */
    @SuppressWarnings("rawtypes")
    SshFuture switchToNoneCipher() throws IOException;

}
