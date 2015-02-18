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

import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;

import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.session.ConnectionService;

/**
 * This interface allows retrieving all the <code>NamedFactory</code> used
 * in the SSH protocol.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface FactoryManager {

    /**
     * Key used to retrieve the value of the window size in the
     * configuration properties map.
     */
    public static final String WINDOW_SIZE = "window-size";

    /**
     * Key used to retrieve the value of the maximum packet size
     * in the configuration properties map.
     */
    public static final String MAX_PACKET_SIZE = "packet-size";

    /**
     * Number of NIO worker threads to use.
     */
    public static final String NIO_WORKERS = "nio-workers";

    /**
     * Default number of worker threads to use.
     */
    public static final int DEFAULT_NIO_WORKERS = Runtime.getRuntime().availableProcessors() + 1;

    /**
     * Key used to retrieve the value of the timeout after which
     * it will close the connection if the other side has not been
     * authenticated.
     */
    public static final String AUTH_TIMEOUT = "auth-timeout";

    /**
     * Key used to retrieve the value of idle timeout after which
     * it will close the connection.  In milliseconds.
     */
    public static final String IDLE_TIMEOUT = "idle-timeout";

    /**
     * Key used to retrieve the value of the disconnect timeout which
     * is used when a disconnection is attempted.  If the disconnect
     * message has not been sent before the timeout, the underlying socket
     * will be forcibly closed.
     */
    public static final String DISCONNECT_TIMEOUT = "disconnect-timeout";

    /**
     * Key used to configure the timeout used when writing a close request
     * on a channel. If the message can not be written before the specified
     * timeout elapses, the channel will be immediately closed. In milliseconds.
     */
    public static final String CHANNEL_CLOSE_TIMEOUT = "channel-close-timeout";

    /**
     * Socket backlog.
     * See {@link java.nio.channels.AsynchronousServerSocketChannel#bind(java.net.SocketAddress, int)}
     */
    public static final String SOCKET_BACKLOG = "socket-backlog";

    /**
     * Socket keep-alive.
     * See {@link java.net.StandardSocketOptions#SO_KEEPALIVE}
     */
    public static final String SOCKET_KEEPALIVE = "socket-keepalive";

    /**
     * Socket send buffer size.
     * See {@link java.net.StandardSocketOptions#SO_SNDBUF}
     */
    public static final String SOCKET_SNDBUF = "socket-sndbuf";

    /**
     * Socket receive buffer size.
     * See {@link java.net.StandardSocketOptions#SO_RCVBUF}
     */
    public static final String SOCKET_RCVBUF = "socket-rcvbuf";

    /**
     * Socket reuse address.
     * See {@link java.net.StandardSocketOptions#SO_REUSEADDR}
     */
    public static final String SOCKET_REUSEADDR = "socket-reuseaddr";

    /**
     * Socket linger.
     * See {@link java.net.StandardSocketOptions#SO_LINGER}
     */
    public static final String SOCKET_LINGER = "socket-linger";

    /**
     * Socket tcp no-delay.
     * See {@link java.net.StandardSocketOptions#TCP_NODELAY}
     */
    public static final String TCP_NODELAY = "tcp-nodelay";

    /**
     * A map of properties that can be used to configure the SSH server
     * or client.  This map will never be changed by either the server or
     * client and is not supposed to be changed at runtime (changes are not
     * bound to have any effect on a running client or server), though it may
     * affect the creation of sessions later as these values are usually not
     * cached.
     *
     * @return a valid <code>Map</code> containing configuration values, never <code>null</code>
     */
    Map<String,String> getProperties();

    /**
     * An upper case string identifying the version of the
     * software used on client or server side.
     * This version includes the name of the software and usually
     * looks like: <code>SSHD-1.0</code>
     *
     * @return the version of the software
     */
    String getVersion();

    IoServiceFactory getIoServiceFactory();

    /**
     * Retrieve the list of named factories for <code>KeyExchange</code>.
     *
     * @return a list of named <code>KeyExchange</code> factories, never <code>null</code>
     */
    List<NamedFactory<KeyExchange>> getKeyExchangeFactories();

    /**
     * Retrieve the list of named factories for <code>Cipher</code>.
     *
     * @return a list of named <code>Cipher</code> factories, never <code>null</code>
     */
    List<NamedFactory<Cipher>> getCipherFactories();

    /**
     * Retrieve the list of named factories for <code>Compression</code>.
     *
     * @return a list of named <code>Compression</code> factories, never <code>null</code>
     */
    List<NamedFactory<Compression>> getCompressionFactories();

    /**
     * Retrieve the list of named factories for <code>Mac</code>.
     *
     * @return a list of named <code>Mac</code> factories, never <code>null</code>
     */
    List<NamedFactory<Mac>> getMacFactories();

    /**
     * Retrieve the list of named factories for <code>Signature</code>.
     *
     * @return a list of named <code>Signature</code> factories, never <code>null</code>
     */
    List<NamedFactory<Signature>> getSignatureFactories();

    /**
     * Retrieve the <code>KeyPairProvider</code> that will be used to find
     * the host key to use on the server side or the user key on the client side.
     *
     * @return the <code>KeyPairProvider</code>, never <code>null</code>
     */
    KeyPairProvider getKeyPairProvider();

    /**
     * Retrieve the <code>Random</code> factory to be used.
     *
     * @return the <code>Random</code> factory, never <code>null</code>
     */
    Factory<Random> getRandomFactory();

    /**
     * Retrieve the list of named factories for <code>Channel</code> objects.
     *
     * @return a list of named <code>Channel</code> factories, never <code>null</code>
     */
    List<NamedFactory<Channel>> getChannelFactories();

    /**
     * Retrieve the agent factory for creating <code>SshAgent</code> objects.
     *
     * @return the factory
     */
    SshAgentFactory getAgentFactory();

    /**
     * Retrieve the <code>ScheduledExecutorService</code> to be used.
     *
     * @return the <code>ScheduledExecutorService</code>, never <code>null</code>
     */
    ScheduledExecutorService getScheduledExecutorService();

    /**
     * Retrieve the <code>ForwardingFilter</code> to be used by the SSH server.
     * If no filter has been configured (i.e. this method returns
     * <code>null</code>), then all forwarding requests will be rejected.
     *
     * @return the <code>ForwardingFilter</code> or <code>null</code>
     */
    ForwardingFilter getTcpipForwardingFilter();

    /**
     * Retrieve the tcpip forwarder factory used to support tcpip forwarding.
     *
     * @return the <code>TcpipForwarderFactory</code>
     */
    TcpipForwarderFactory getTcpipForwarderFactory();

    /**
     * Retrieve the <code>FileSystemFactory</code> to be used to traverse the file system.
     *
     * @return a valid <code>FileSystemFactory</code> object or <code>null</code> if file based
     *         interactions are not supported on this server
     */
    FileSystemFactory getFileSystemFactory();

    /**
     * Retrieve the list of SSH <code>Service</code> factories.
     *
     * @return a list of named <code>Service</code> factories, never <code>null</code>
     */
    List<ServiceFactory> getServiceFactories();

    /**
     * Retrieve the list of global request handlers.
     *
     * @return a list of named <code>GlobalRequestHandler</code>
     */
    List<RequestHandler<ConnectionService>> getGlobalRequestHandlers();

}
