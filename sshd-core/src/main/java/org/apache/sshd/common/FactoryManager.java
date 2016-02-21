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
package org.apache.sshd.common;

import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelListenerManager;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.forward.TcpipForwarderFactory;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.kex.KexFactoryManager;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.ReservedSessionMessagesManager;
import org.apache.sshd.common.session.SessionListenerManager;
import org.apache.sshd.server.forward.ForwardingFilter;

/**
 * This interface allows retrieving all the <code>NamedFactory</code> used
 * in the SSH protocol.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface FactoryManager
        extends KexFactoryManager,
                SessionListenerManager,
                ReservedSessionMessagesManager,
                ChannelListenerManager,
                AttributeStore,
                PropertyResolver {

    /**
     * Key used to retrieve the value of the channel window size in the
     * configuration properties map.
     * @see #DEFAULT_WINDOW_SIZE
     */
    String WINDOW_SIZE = "window-size";

    /**
     * Default {@link #WINDOW_SIZE} if none set
     */
    int DEFAULT_WINDOW_SIZE = 0x200000;

    /**
     * Key used to retrieve timeout (msec.) to wait for data to
     * become available when reading from a channel. If not set
     * or non-positive then infinite value is assumed
     * @see #DEFAULT_WINDOW_TIMEOUT
     */
    String WINDOW_TIMEOUT = "window-timeout";

    /**
     * Default {@link #WINDOW_TIMEOUT} value
     */
    long DEFAULT_WINDOW_TIMEOUT = 0L;

    /**
     * Key used to retrieve the value of the maximum packet size
     * in the configuration properties map.
     * @see #DEFAULT_MAX_PACKET_SIZE
     */
    String MAX_PACKET_SIZE = "packet-size";

    /**
     * Default {@link #MAX_PACKET_SIZE} if none set
     */
    int DEFAULT_MAX_PACKET_SIZE = 0x8000;

    /**
     * Number of NIO worker threads to use.
     * @see #DEFAULT_NIO_WORKERS
     */
    String NIO_WORKERS = "nio-workers";

    /**
     * Default number of worker threads to use if none set - the number
     * of available processors + 1
     */
    int DEFAULT_NIO_WORKERS = Runtime.getRuntime().availableProcessors() + 1;

    /**
     * Key used to retrieve the value of the timeout after which
     * it will close the connection if the other side has not been
     * authenticated - in milliseconds.
     * @see #DEFAULT_AUTH_TIMEOUT
     */
    String AUTH_TIMEOUT = "auth-timeout";

    /**
     * Default value for {@link #AUTH_TIMEOUT} if none set
     */
    long DEFAULT_AUTH_TIMEOUT = TimeUnit.MINUTES.toMillis(2L);

    /**
     * Key used to retrieve the value of idle timeout after which
     * it will close the connection - in milliseconds.
     * @see #DEFAULT_IDLE_TIMEOUT
     */
    String IDLE_TIMEOUT = "idle-timeout";

    /**
     * Default value for {@link #IDLE_TIMEOUT} if none set
     */
    long DEFAULT_IDLE_TIMEOUT = TimeUnit.MINUTES.toMillis(10L);

    /**
     * Key used to retrieve the value of the disconnect timeout which
     * is used when a disconnection is attempted.  If the disconnect
     * message has not been sent before the timeout, the underlying socket
     * will be forcibly closed - in milliseconds.
     * @see #DEFAULT_DISCONNECT_TIMEOUT
     */
    String DISCONNECT_TIMEOUT = "disconnect-timeout";

    /**
     * Default value for {@link #DISCONNECT_TIMEOUT} if none set
     */
    long DEFAULT_DISCONNECT_TIMEOUT = TimeUnit.SECONDS.toMillis(10L);

    /**
     * Key used to configure the timeout used when writing a close request
     * on a channel. If the message can not be written before the specified
     * timeout elapses, the channel will be immediately closed. In milliseconds.
     * @see #DEFAULT_AUTH_TIMEOUT
     */
    String CHANNEL_CLOSE_TIMEOUT = "channel-close-timeout";

    /**
     * Default {@link #CHANNEL_CLOSE_TIMEOUT} value if none set
     */
    long DEFAULT_CHANNEL_CLOSE_TIMEOUT = TimeUnit.SECONDS.toMillis(5L);

    /**
     * Timeout (milliseconds) to wait for client / server stop request
     * if immediate stop requested.
     * @see #DEFAULT_STOP_WAIT_TIME
     */
    String STOP_WAIT_TIME = "stop-wait-time";

    /**
     * Default value for {@link #STOP_WAIT_TIME} if none specified
     */
    long DEFAULT_STOP_WAIT_TIME = TimeUnit.MINUTES.toMillis(1L);

    /**
     * Socket backlog.
     * See {@link java.nio.channels.AsynchronousServerSocketChannel#bind(java.net.SocketAddress, int)}
     */
    String SOCKET_BACKLOG = "socket-backlog";

    /**
     * Socket keep-alive.
     * See {@link java.net.StandardSocketOptions#SO_KEEPALIVE}
     */
    String SOCKET_KEEPALIVE = "socket-keepalive";

    /**
     * Socket send buffer size.
     * See {@link java.net.StandardSocketOptions#SO_SNDBUF}
     */
    String SOCKET_SNDBUF = "socket-sndbuf";

    /**
     * Socket receive buffer size.
     * See {@link java.net.StandardSocketOptions#SO_RCVBUF}
     */
    String SOCKET_RCVBUF = "socket-rcvbuf";

    /**
     * Socket reuse address.
     * See {@link java.net.StandardSocketOptions#SO_REUSEADDR}
     */
    String SOCKET_REUSEADDR = "socket-reuseaddr";

    /**
     * Socket linger.
     * See {@link java.net.StandardSocketOptions#SO_LINGER}
     */
    String SOCKET_LINGER = "socket-linger";

    /**
     * Socket tcp no-delay.
     * See {@link java.net.StandardSocketOptions#TCP_NODELAY}
     */
    String TCP_NODELAY = "tcp-nodelay";

    /**
     * Read buffer size for NIO2 sessions
     * See {@link org.apache.sshd.common.io.nio2.Nio2Session}
     */
    String NIO2_READ_BUFFER_SIZE = "nio2-read-buf-size";

    /**
     * The default reported version of {@link #getVersion()} if the built-in
     * version information cannot be accessed
     */
    String DEFAULT_VERSION = "SSHD-UNKNOWN";

    /**
     * Maximum allowed size of the initial identification text sent during
     * the handshake
     */
    String MAX_IDENTIFICATION_SIZE = "max-identification-size";

    /**
     * Default value for {@link #MAX_IDENTIFICATION_SIZE} if none set
     */
    int DEFAULT_MAX_IDENTIFICATION_SIZE = 16 * 1024;

    /**
     * Key re-exchange will be automatically performed after the session
     * has sent or received the given amount of bytes. If non-positive,
     * then disabled. The default value is {@link #DEFAULT_REKEY_BYTES_LIMIT}
     */
    String REKEY_BYTES_LIMIT = "rekey-bytes-limit";

    /**
     * Default value for {@link #REKEY_BYTES_LIMIT} if no override
     * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-9">RFC4253 section 9</A>
     */
    long DEFAULT_REKEY_BYTES_LIMIT = 1024L * 1024L * 1024L; // 1GB

    /**
     * Key re-exchange will be automatically performed after the specified
     * amount of time has elapsed since the last key exchange - in milliseconds.
     * If non-positive then disabled. The default value is {@link #DEFAULT_REKEY_TIME_LIMIT}
     */
    String REKEY_TIME_LIMIT = "rekey-time-limit";

    /**
     * Default value for {@link #REKEY_TIME_LIMIT} if none specified
     * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-9">RFC4253 section 9</A>
     */
    long DEFAULT_REKEY_TIME_LIMIT = 60L * 60L * 1000L; // 1 hour

    /**
     * Key re-exchange will be automatically performed after the specified
     * number of packets has been exchanged - positive 64-bit value. If
     * non-positive then disabled. The default is {@link #DEFAULT_REKEY_PACKETS_LIMIT}
     */
    String REKEY_PACKETS_LIMIT = "rekey-packets-limit";

    /**
     * Default value for {@link #REKEY_PACKETS_LIMIT} if none specified
     * @see <A HREF="https://tools.ietf.org/html/rfc4344#section-3.1">RFC4344 section 3.1</A>
     */
    long DEFAULT_REKEY_PACKETS_LIMIT = 1L << 31;

    /**
     * Key re-exchange will be automatically performed after the specified
     * number of cipher blocks has been processed - positive 64-bit value. If
     * non-positive then disabled. The default is calculated according to
     * <A HREF="https://tools.ietf.org/html/rfc4344#section-3.2">RFC4344 section 3.2</A>
     */
    String REKEY_BLOCKS_LIMIT = "rekey-blocks-limit";

    /**
     * Average number of packets to be skipped before an {@code SSH_MSG_IGNORE}
     * message is inserted in the stream. If non-positive, then feature is disabled
     * @see #IGNORE_MESSAGE_VARIANCE
     * @see <A HREF="https://tools.ietf.org/html/rfc4251#section-9.3.1">RFC4251 section 9.3.1</A>
     */
    String IGNORE_MESSAGE_FREQUENCY = "ignore-message-frequency";

    /**
     * Default value of {@link #IGNORE_MESSAGE_FREQUENCY} if none set.
     */
    long DEFAULT_IGNORE_MESSAGE_FREQUENCY = 1024L;

    /**
     * The variance to be used around the configured {@link #IGNORE_MESSAGE_FREQUENCY}
     * value in order to avoid insertion at a set frequency. If zero, then <U>exact</U>
     * frequency is used. If negative, then the <U>absolute</U> value is used. If
     * greater or equal to the frequency, then assumed to be zero - i.e., no variance
     * @see <A HREF="https://tools.ietf.org/html/rfc4251#section-9.3.1">RFC4251 section 9.3.1</A>
     */
    String IGNORE_MESSAGE_VARIANCE = "ignore-message-variance";

    /**
     * Default value for {@link #IGNORE_MESSAGE_VARIANCE} if none configured
     */
    int DEFAULT_IGNORE_MESSAGE_VARIANCE = 32;

    /**
     * Minimum size of {@code SSH_MSG_IGNORE} payload to send if feature enabled. If
     * non-positive then no message is sent. Otherwise, the actual size is between this
     * size and twice its value
     * @see <A HREF="https://tools.ietf.org/html/rfc4251#section-9.3.1">RFC4251 section 9.3.1</A>
     */
    String IGNORE_MESSAGE_SIZE = "ignore-message-size";

    /**
     * Value of {@link #IGNORE_MESSAGE_SIZE} if none configured
     */
    int DEFAULT_IGNORE_MESSAGE_SIZE = 16;

    /**
     * An upper case string identifying the version of the software used on client or server side.
     * This version includes the name and version of the software and usually looks like this:
     * <code>SSHD-CORE-1.0</code>
     *
     * @return the version of the software
     */
    String getVersion();

    IoServiceFactory getIoServiceFactory();

    /**
     * Retrieve the <code>Random</code> factory to be used.
     *
     * @return The <code>Random</code> factory, never {@code null}
     */
    Factory<Random> getRandomFactory();

    /**
     * Retrieve the list of named factories for <code>Channel</code> objects.
     *
     * @return A list of named <code>Channel</code> factories, never {@code null}
     */
    List<NamedFactory<Channel>> getChannelFactories();

    /**
     * Retrieve the agent factory for creating <code>SshAgent</code> objects.
     *
     * @return The {@link SshAgentFactory}
     */
    SshAgentFactory getAgentFactory();

    /**
     * Retrieve the <code>ScheduledExecutorService</code> to be used.
     *
     * @return The {@link ScheduledExecutorService}, never {@code null}
     */
    ScheduledExecutorService getScheduledExecutorService();

    /**
     * Retrieve the <code>ForwardingFilter</code> to be used by the SSH server.
     * If no filter has been configured (i.e. this method returns
     * {@code null}), then all forwarding requests will be rejected.
     *
     * @return The {@link ForwardingFilter} or {@code null}
     */
    ForwardingFilter getTcpipForwardingFilter();

    /**
     * Retrieve the tcpip forwarder factory used to support tcpip forwarding.
     *
     * @return The {@link TcpipForwarderFactory}
     */
    TcpipForwarderFactory getTcpipForwarderFactory();

    /**
     * Retrieve the <code>FileSystemFactory</code> to be used to traverse the file system.
     *
     * @return a valid {@link FileSystemFactory} instance or {@code null} if file based
     * interactions are not supported on this server
     */
    FileSystemFactory getFileSystemFactory();

    /**
     * Retrieve the list of SSH <code>Service</code> factories.
     *
     * @return a list of named <code>Service</code> factories, never {@code null}
     */
    List<ServiceFactory> getServiceFactories();

    /**
     * Retrieve the list of global request handlers.
     *
     * @return a list of named <code>GlobalRequestHandler</code>
     */
    List<RequestHandler<ConnectionService>> getGlobalRequestHandlers();

}
