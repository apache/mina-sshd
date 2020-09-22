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
package org.apache.sshd.core;

import java.io.IOException;
import java.nio.charset.Charset;
import java.time.Duration;

import org.apache.sshd.client.config.keys.ClientIdentityLoader;
import org.apache.sshd.common.Property;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.auth.WelcomeBannerPhase;
import org.apache.sshd.server.channel.ChannelDataReceiver;

/**
 * Configurable properties for sshd-core.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class CoreModuleProperties {

    /**
     * Value that can be set in order to control the type of authentication channel being requested when forwarding a
     * PTY session.
     */
    public static final Property<String> PROXY_AUTH_CHANNEL_TYPE
            = Property.string("ssh-agent-factory-proxy-auth-channel-type", "auth-agent-req@openssh.com");

    /**
     * See {@link org.apache.sshd.agent.local.ProxyAgentFactory#getChannelForwardingFactories}
     */
    public static final Property<Boolean> PREFER_UNIX_AGENT
            = Property.bool("ssh-prefer-unix-agent", OsUtils.isUNIX());

    /**
     * Value that can be set on the {@link org.apache.sshd.common.FactoryManager} or the session to configure the
     * channel open timeout value (millis).
     */
    public static final Property<Duration> CHANNEL_OPEN_TIMEOUT
            = Property.duration("ssh-agent-server-channel-open-timeout", Duration.ofSeconds(30));

    /**
     * Value used to configure the type of proxy forwarding channel to be used. See also
     * https://tools.ietf.org/html/draft-ietf-secsh-agent-02
     */
    public static final Property<String> PROXY_CHANNEL_TYPE
            = Property.string("ssh-agent-server-channel-proxy-type", "auth-agent@openssh.com");

    /**
     * Property that can be set on the {@link Session} in order to control the authentication timeout (millis).
     */
    public static final Property<Duration> AUTH_SOCKET_TIMEOUT
            = Property.duration("ssh-agent-server-proxy-auth-socket-timeout", Duration.ofHours(1));

    public static final int DEFAULT_FORWARDER_BUF_SIZE = 1024;
    public static final int MIN_FORWARDER_BUF_SIZE = 127;
    public static final int MAX_FORWARDER_BUF_SIZE = 32767;

    /**
     * Property that can be set on the factory manager in order to control the buffer size used to forward data from the
     * established channel
     *
     * @see #MIN_FORWARDER_BUF_SIZE
     * @see #MAX_FORWARDER_BUF_SIZE
     * @see #DEFAULT_FORWARDER_BUF_SIZE
     */
    public static final Property<Integer> FORWARDER_BUFFER_SIZE
            = Property.integer("channel-agent-fwd-buf-size", DEFAULT_FORWARDER_BUF_SIZE);

    /**
     * Ordered comma separated list of authentications methods. Authentications methods accepted by the server will be
     * tried in the given order. If not configured or {@code null}/empty, then the session's
     * {@link org.apache.sshd.client.ClientAuthenticationManager#getUserAuthFactories()} is used as-is
     */
    public static final Property<String> PREFERRED_AUTHS
            = Property.string("preferred-auths");

    /**
     * Specifies the number of interactive prompts before giving up. The argument to this keyword must be an integer.
     */
    public static final Property<Integer> PASSWORD_PROMPTS
            = Property.integer("password-prompts", 3);

    /**
     * Key used to retrieve the value of the client identification string. If set, then it is <U>appended</U> to the
     * (standard) &quot;SSH-2.0-&quot; prefix. Otherwise a default is sent that consists of &quot;SSH-2.0-&quot; plus
     * the current SSHD artifact name and version in uppercase - e.g., &quot;SSH-2.0-APACHE-SSHD-1.0.0&quot;
     */
    public static final Property<String> CLIENT_IDENTIFICATION
            = Property.string("client-identification");

    /**
     * Whether to send the identification string immediately upon session connection being established or wait for the
     * server's identification before sending our own.
     *
     * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-4.2">RFC 4253 - section 4.2 - Protocol Version
     *      Exchange</A>
     */
    public static final Property<Boolean> SEND_IMMEDIATE_IDENTIFICATION
            = Property.bool("send-immediate-identification", true);

    /**
     * Whether to send {@code SSH_MSG_KEXINIT} immediately after sending the client identification string or wait until
     * the severer's one has been received.
     *
     * @see #SEND_IMMEDIATE_IDENTIFICATION
     */
    public static final Property<Boolean> SEND_IMMEDIATE_KEXINIT
            = Property.bool("send-immediate-kex-init", true);

    /**
     * Key used to set the heartbeat interval in milliseconds (0 to disable = default)
     */
    public static final Property<Duration> HEARTBEAT_INTERVAL
            = Property.duration("heartbeat-interval", Duration.ZERO);

    /**
     * Key used to check the heartbeat request that should be sent to the server
     */
    public static final Property<String> HEARTBEAT_REQUEST
            = Property.string("heartbeat-request", "keepalive@sshd.apache.org");

    /**
     * Key used to indicate that the heartbeat request is also expecting a reply - time in <U>milliseconds</U> to wait
     * for the reply. If non-positive then no reply is expected (nor requested).
     */
    public static final Property<Duration> HEARTBEAT_REPLY_WAIT
            = Property.durationSec("heartbeat-reply-wait", Duration.ofMinutes(5));

    /**
     * Whether to ignore invalid identities files when pre-initializing the client session
     *
     * @see ClientIdentityLoader#isValidLocation(org.apache.sshd.common.NamedResource)
     */
    public static final Property<Boolean> IGNORE_INVALID_IDENTITIES
            = Property.bool("ignore-invalid-identities", true);

    /**
     * Defines if we should abort in case we encounter an invalid (e.g. expired) openssh certificate.
     */
    public static final Property<Boolean> ABORT_ON_INVALID_CERTIFICATE
            = Property.bool("abort-on-invalid-certificate", false);

    /**
     * As per RFC-4256:
     *
     * The language tag is deprecated and SHOULD be the empty string. It may be removed in a future revision of this
     * specification. Instead, the server SHOULD select the language to be used based on the tags communicated during
     * key exchange
     */
    public static final Property<String> INTERACTIVE_LANGUAGE_TAG
            = Property.string("kb-client-interactive-language-tag", "");

    /**
     * As per RFC-4256:
     *
     * The submethods field is included so the user can give a hint of which actual methods he wants to use. It is a
     * comma-separated list of authentication submethods (software or hardware) that the user prefers. If the client has
     * knowledge of the submethods preferred by the user, presumably through a configuration setting, it MAY use the
     * submethods field to pass this information to the server. Otherwise, it MUST send the empty string.
     *
     * The actual names of the submethods is something the user and the server need to agree upon.
     *
     * Server interpretation of the submethods field is implementation- dependent.
     */
    public static final Property<String> INTERACTIVE_SUBMETHODS
            = Property.string("kb-client-interactive-sub-methods", "");

    /**
     * Configure whether reply for the &quot;exec&quot; request is required
     */
    public static final Property<Boolean> REQUEST_EXEC_REPLY
            = Property.bool("channel-exec-want-reply", false);

    /**
     * On some platforms, a call to {@ode System.in.read(new byte[65536], 0, 32768)} always throws an
     * {@link IOException}. So we need to protect against that and chunk the call into smaller calls. This problem was
     * found on Windows, JDK 1.6.0_03-b05.
     */
    public static final Property<Integer> INPUT_STREAM_PUMP_CHUNK_SIZE
            = Property.integer("stdin-pump-chunk-size", 1024);

    /**
     * Configure whether reply for the &quot;shell&quot; request is required
     */
    public static final Property<Boolean> REQUEST_SHELL_REPLY
            = Property.bool("channel-shell-want-reply", false);

    /**
     * Configure whether reply for the &quot;subsystem&quoot; request is required
     *
     * <P>
     * Default value for {@link #REQUEST_SUBSYSTEM_REPLY} - according to
     * <A HREF="https://tools.ietf.org/html/rfc4254#section-6.5">RFC4254 section 6.5:</A>
     * </P>
     * <P>
     * It is RECOMMENDED that the reply to these messages be requested and checked.
     * </P>
     */
    public static final Property<Boolean> REQUEST_SUBSYSTEM_REPLY
            = Property.bool("channel-subsystem-want-reply", true);

    public static final Property<Integer> PROP_DHGEX_CLIENT_MIN_KEY
            = Property.integer("dhgex-client-min");

    public static final Property<Integer> PROP_DHGEX_CLIENT_MAX_KEY
            = Property.integer("dhgex-client-max");

    public static final Property<Integer> PROP_DHGEX_CLIENT_PRF_KEY
            = Property.integer("dhgex-client-prf");

    /**
     * Key used to retrieve the value of the channel window size in the configuration properties map.
     */
    public static final Property<Long> WINDOW_SIZE
            = Property.long_("window-size", 0x200000L);

    /**
     * Key used to retrieve timeout (msec.) to wait for data to become available when reading from a channel. If not set
     * or non-positive then infinite value is assumed
     */
    public static final Property<Duration> WINDOW_TIMEOUT
            = Property.duration("window-timeout", Duration.ZERO);

    /**
     * Key used to retrieve the value of the maximum packet size in the configuration properties map.
     */
    public static final Property<Long> MAX_PACKET_SIZE
            = Property.long_("packet-size", 0x8000L);

    /**
     * A safety value that is designed to avoid an attack that uses large channel packet sizes
     */
    public static final Property<Long> LIMIT_PACKET_SIZE
            = Property.long_("max-packet-size", Integer.MAX_VALUE / 4L);

    /**
     * Number of NIO worker threads to use.
     */
    public static final Property<Integer> NIO_WORKERS
            = Property.validating(Property.integer("nio-workers", Runtime.getRuntime().availableProcessors() + 1),
                    w -> ValidateUtils.checkTrue(w > 0, "Number of NIO workers must be positive: %d", w));

    /**
     * Key used to retrieve the value of the timeout after which it will close the connection if the other side has not
     * been authenticated - in milliseconds.
     */
    public static final Property<Duration> AUTH_TIMEOUT
            = Property.duration("auth-timeout", Duration.ofMinutes(2));

    /**
     * Key used to retrieve the value of idle timeout after which it will close the connection - in milliseconds.
     */
    public static final Property<Duration> IDLE_TIMEOUT
            = Property.duration("idle-timeout", Duration.ofMinutes(10));

    /**
     * Key used to retrieve the value of the socket read timeout for NIO2 session implementation - in milliseconds.
     */
    public static final Property<Duration> NIO2_READ_TIMEOUT
            = Property.duration("nio2-read-timeout", Duration.ZERO);

    /**
     * Minimum NIO2 write wait timeout for a single outgoing packet - in milliseconds
     */
    public static final Property<Duration> NIO2_MIN_WRITE_TIMEOUT
            = Property.duration("nio2-min-write-timeout", Duration.ofSeconds(30L));

    /**
     * Key used to retrieve the value of the disconnect timeout which is used when a disconnection is attempted. If the
     * disconnect message has not been sent before the timeout, the underlying socket will be forcibly closed - in
     * milliseconds.
     */
    public static final Property<Duration> DISCONNECT_TIMEOUT
            = Property.duration("disconnect-timeout", Duration.ofSeconds(10));

    /**
     * Key used to configure the timeout used when writing a close request on a channel. If the message can not be
     * written before the specified timeout elapses, the channel will be immediately closed. In milliseconds.
     */
    public static final Property<Duration> CHANNEL_CLOSE_TIMEOUT
            = Property.duration("channel-close-timeout", Duration.ofSeconds(5));

    /**
     * Timeout (milliseconds) to wait for client / server stop request if immediate stop requested.
     */
    public static final Property<Duration> STOP_WAIT_TIME
            = Property.duration("stop-wait-time", Duration.ofMinutes(1));

    /**
     * Socket backlog. See {@link java.nio.channels.AsynchronousServerSocketChannel#bind(java.net.SocketAddress, int)}
     */
    public static final Property<Integer> SOCKET_BACKLOG
            = Property.integer("socket-backlog", 0);

    /**
     * Socket keep-alive. See {@link java.net.StandardSocketOptions#SO_KEEPALIVE}
     */
    public static final Property<Boolean> SOCKET_KEEPALIVE
            = Property.bool("socket-keepalive", false);

    /**
     * Socket send buffer size. See {@link java.net.StandardSocketOptions#SO_SNDBUF}
     */
    public static final Property<Integer> SOCKET_SNDBUF
            = Property.integer("socket-sndbuf");

    /**
     * Socket receive buffer size. See {@link java.net.StandardSocketOptions#SO_RCVBUF}
     */
    public static final Property<Integer> SOCKET_RCVBUF
            = Property.integer("socket-rcvbuf");

    /**
     * Socket reuse address. See {@link java.net.StandardSocketOptions#SO_REUSEADDR}
     */
    public static final Property<Boolean> SOCKET_REUSEADDR
            = Property.bool("socket-reuseaddr", true);
    /**
     * Socket linger. See {@link java.net.StandardSocketOptions#SO_LINGER}
     */
    public static final Property<Integer> SOCKET_LINGER
            = Property.integer("socket-linger", -1);

    /**
     * Socket tcp no-delay. See {@link java.net.StandardSocketOptions#TCP_NODELAY}
     */
    public static final Property<Boolean> TCP_NODELAY
            = Property.bool("tcp-nodelay", false);

    /**
     * Read buffer size for NIO2 sessions See {@link org.apache.sshd.common.io.nio2.Nio2Session}
     */
    public static final Property<Integer> NIO2_READ_BUFFER_SIZE
            = Property.integer("nio2-read-buf-size", 32 * 1024);

    /**
     * Maximum allowed size of the initial identification text sent during the handshake
     */
    public static final Property<Integer> MAX_IDENTIFICATION_SIZE
            = Property.integer("max-identification-size", 16 * 1024);

    /**
     * Key re-exchange will be automatically performed after the session has sent or received the given amount of bytes.
     * If non-positive, then disabled.
     */
    public static final Property<Long> REKEY_BYTES_LIMIT
            = Property.long_("rekey-bytes-limit", 1024L * 1024L * 1024L); // 1GB

    /**
     * Key re-exchange will be automatically performed after the specified amount of time has elapsed since the last key
     * exchange - in milliseconds. If non-positive then disabled.
     *
     * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-9">RFC4253 section 9</A>
     */
    public static final Property<Duration> REKEY_TIME_LIMIT
            = Property.duration("rekey-time-limit", Duration.ofHours(1));

    /**
     * Key re-exchange will be automatically performed after the specified number of packets has been exchanged -
     * positive 64-bit value. If non-positive then disabled.
     *
     * @see <A HREF="https://tools.ietf.org/html/rfc4344#section-3.1">RFC4344 section 3.1</A>
     */
    public static final Property<Long> REKEY_PACKETS_LIMIT
            = Property.long_("rekey-packets-limit", 1L << 31);

    /**
     * Key re-exchange will be automatically performed after the specified number of cipher blocks has been processed -
     * positive 64-bit value. If non-positive then disabled. The default is calculated according to
     * <A HREF="https://tools.ietf.org/html/rfc4344#section-3.2">RFC4344 section 3.2</A>
     */
    public static final Property<Long> REKEY_BLOCKS_LIMIT
            = Property.long_("rekey-blocks-limit", 0L);

    /**
     * Average number of packets to be skipped before an {@code SSH_MSG_IGNORE} message is inserted in the stream. If
     * non-positive, then feature is disabled
     *
     * @see #IGNORE_MESSAGE_VARIANCE
     * @see <A HREF="https://tools.ietf.org/html/rfc4251#section-9.3.1">RFC4251 section 9.3.1</A>
     */
    public static final Property<Long> IGNORE_MESSAGE_FREQUENCY
            = Property.long_("ignore-message-frequency", 1024L);

    /**
     * The variance to be used around the configured {@link #IGNORE_MESSAGE_FREQUENCY} value in order to avoid insertion
     * at a set frequency. If zero, then <U>exact</U> frequency is used. If negative, then the <U>absolute</U> value is
     * used. If greater or equal to the frequency, then assumed to be zero - i.e., no variance
     *
     * @see <A HREF="https://tools.ietf.org/html/rfc4251#section-9.3.1">RFC4251 section 9.3.1</A>
     */
    public static final Property<Integer> IGNORE_MESSAGE_VARIANCE
            = Property.integer("ignore-message-variance", 32);

    /**
     * Minimum size of {@code SSH_MSG_IGNORE} payload to send if feature enabled. If non-positive then no message is
     * sent. Otherwise, the actual size is between this size and twice its value
     *
     * @see <A HREF="https://tools.ietf.org/html/rfc4251#section-9.3.1">RFC4251 section 9.3.1</A>
     */
    public static final Property<Integer> IGNORE_MESSAGE_SIZE
            = Property.integer("ignore-message-size", 16);

    /**
     * The request type of agent forwarding. The value may be {@value #AGENT_FORWARDING_TYPE_IETF} or
     * {@value #AGENT_FORWARDING_TYPE_OPENSSH}.
     */
    public static final String AGENT_FORWARDING_TYPE = "agent-fw-auth-type";

    /**
     * The agent forwarding type defined by IETF (https://tools.ietf.org/html/draft-ietf-secsh-agent-02).
     */
    public static final String AGENT_FORWARDING_TYPE_IETF = "auth-agent-req";

    /**
     * The agent forwarding type defined by OpenSSH.
     */
    public static final String AGENT_FORWARDING_TYPE_OPENSSH = "auth-agent-req@openssh.com";

    /**
     * Configure max. wait time (millis) to wait for space to become available
     */
    public static final Property<Duration> WAIT_FOR_SPACE_TIMEOUT
            = Property.duration("channel-output-wait-for-space-timeout", Duration.ofSeconds(30L));

    /**
     * Used to configure the timeout (milliseconds) for receiving a response for the forwarding request
     */
    public static final Property<Duration> FORWARD_REQUEST_TIMEOUT
            = Property.duration("tcpip-forward-request-timeout", Duration.ofSeconds(15L));

    /**
     * Property that can be used to configure max. allowed concurrent active channels
     *
     * @see org.apache.sshd.common.session.ConnectionService#registerChannel(Channel)
     */
    public static final Property<Integer> MAX_CONCURRENT_CHANNELS
            = Property.integer("max-sshd-channels", Integer.MAX_VALUE);

    /**
     * RFC4254 does not clearly specify how to handle {@code SSH_MSG_CHANNEL_DATA} and
     * {@code SSH_MSG_CHANNEL_EXTENDED_DATA} received through an unknown channel. Therefore, we provide a configurable
     * approach to it with the default set to ignore it.
     */
    public static final Property<Boolean> SEND_REPLY_FOR_CHANNEL_DATA
            = Property.bool("send-unknown-channel-data-reply", false);

    /**
     * Key used to retrieve the value in the configuration properties map of the maximum number of failed authentication
     * requests before the server closes the connection.
     */
    public static final Property<Integer> MAX_AUTH_REQUESTS
            = Property.integer("max-auth-requests", 20);

    /**
     * Key used to retrieve the value of welcome banner that will be displayed when a user connects to the server. If
     * {@code null}/empty then no banner will be sent. The value can be one of the following:
     * <UL>
     * <P>
     * <LI>A {@link java.io.File} or {@link java.nio.file.Path}, in which case its contents will be transmitted.
     * <B>Note:</B> if the file is empty or does not exits, no banner will be transmitted.</LI>
     * </P>
     *
     * <P>
     * <LI>A {@link java.net.URI} or a string starting with &quot;file:/&quot;, in which case it will be converted to a
     * {@link java.nio.file.Path} and handled accordingly.</LI>
     * </P>
     *
     * <P>
     * <LI>A string containing a special value indicator - e.g., {@link #AUTO_WELCOME_BANNER_VALUE}, in which case the
     * relevant banner content will be generated.</LI>
     * </P>
     *
     * <P>
     * <LI>Any other object whose {@code toString()} value yields a non empty string will be used as the banner
     * contents.</LI>
     * </P>
     * </UL>
     *
     * @see <A HREF="https://tools.ietf.org/html/rfc4252#section-5.4">RFC-4252 section 5.4</A>
     */
    public static final Property<Object> WELCOME_BANNER
            = Property.object("welcome-banner");

    /**
     * Special value that can be set for the {@link #WELCOME_BANNER} property indicating that the server should generate
     * a banner consisting of the random art of the server's keys (if any are provided). If no server keys are
     * available, then no banner will be sent
     */
    public static final String AUTO_WELCOME_BANNER_VALUE = "#auto-welcome-banner";

    /**
     * Key used to denote the language code for the welcome banner (if such a banner is configured).
     */
    public static final Property<String> WELCOME_BANNER_LANGUAGE
            = Property.string("welcome-banner-language", "en");

    /**
     * The {@link WelcomeBannerPhase} value - either as an enum or a string
     */
    public static final Property<WelcomeBannerPhase> WELCOME_BANNER_PHASE
            = Property.enum_("welcome-banner-phase", WelcomeBannerPhase.class, WelcomeBannerPhase.IMMEDIATE);

    /**
     * The charset to use if the configured welcome banner points to a file - if not specified (either as a string or a
     * {@link java.nio.charset.Charset} then the local default is used.
     */
    public static final Property<Charset> WELCOME_BANNER_CHARSET
            = Property.charset("welcome-banner-charset", Charset.defaultCharset());

    /**
     * This key is used when configuring multi-step authentications. The value needs to be a blank separated list of
     * comma separated list of authentication method names. For example, an argument of
     * <code>publickey,password publickey,keyboard-interactive</code> would require the user to complete public key
     * authentication, followed by either password or keyboard interactive authentication. Only methods that are next in
     * one or more lists are offered at each stage, so for this example, it would not be possible to attempt password or
     * keyboard-interactive authentication before public key.
     */
    public static final Property<String> AUTH_METHODS
            = Property.string("auth-methods");

    /**
     * Key used to retrieve the value of the maximum concurrent open session count per username. If not set, then
     * unlimited
     */
    public static final Property<Integer> MAX_CONCURRENT_SESSIONS
            = Property.integer("max-concurrent-sessions");

    /**
     * Key used to retrieve any extra lines to be sent during initial protocol handshake <U>before</U> the
     * identification. The configured string value should use {@value #SERVER_EXTRA_IDENT_LINES_SEPARATOR} character to
     * denote line breaks
     */
    public static final Property<String> SERVER_EXTRA_IDENTIFICATION_LINES
            = Property.string("server-extra-identification-lines");

    /**
     * Separator used in the {@link #SERVER_EXTRA_IDENTIFICATION_LINES} configuration string to indicate new line break
     */
    public static final char SERVER_EXTRA_IDENT_LINES_SEPARATOR = '|';

    /**
     * Key used to retrieve the value of the server identification string. If set, then it is <U>appended</U> to the
     * (standard) &quot;SSH-2.0-&quot; prefix. Otherwise a default is sent that consists of &quot;SSH-2.0-&quot; plus
     * the current SSHD artifact name and version in uppercase - e.g., &quot;SSH-2.0-APACHE-SSHD-1.0.0&quot;
     */
    public static final Property<String> SERVER_IDENTIFICATION
            = Property.string("server-identification");

    /**
     * Key used to configure the timeout used when receiving a close request on a channel to wait until the command
     * cleanly exits after setting an EOF on the input stream.
     */
    public static final Property<Duration> COMMAND_EXIT_TIMEOUT
            = Property.duration("command-exit-timeout", Duration.ofMillis(5L));

    /**
     * A URL pointing to the moduli file. If not specified, the default internal file will be used.
     */
    public static final Property<String> MODULI_URL
            = Property.string("moduli-url");

    /**
     * See {@link org.apache.sshd.server.auth.keyboard.DefaultKeyboardInteractiveAuthenticator}.
     */
    public static final Property<String> KB_SERVER_INTERACTIVE_NAME
            = Property.string("kb-server-interactive-name", "Password authentication");

    /**
     * See {@link org.apache.sshd.server.auth.keyboard.DefaultKeyboardInteractiveAuthenticator}.
     */
    public static final Property<String> KB_SERVER_INTERACTIVE_INSTRUCTION
            = Property.string("kb-server-interactive-instruction", "");

    /**
     * See {@link org.apache.sshd.server.auth.keyboard.DefaultKeyboardInteractiveAuthenticator}.
     */
    public static final Property<String> KB_SERVER_INTERACTIVE_LANG
            = Property.string("kb-server-interactive-language", "en-US");

    /**
     * See {@link org.apache.sshd.server.auth.keyboard.DefaultKeyboardInteractiveAuthenticator}.
     */
    public static final Property<String> KB_SERVER_INTERACTIVE_PROMPT
            = Property.string("kb-server-interactive-prompt", "Password: ");

    /**
     * See {@link org.apache.sshd.server.auth.keyboard.DefaultKeyboardInteractiveAuthenticator}.
     */
    public static final Property<Boolean> KB_SERVER_INTERACTIVE_ECHO_PROMPT
            = Property.bool("kb-server-interactive-echo-prompt", false);

    /**
     * Maximum amount of extended (a.k.a. STDERR) data allowed to be accumulated until a {@link ChannelDataReceiver} for
     * the data is registered
     */
    public static final Property<Integer> MAX_EXTDATA_BUFSIZE
            = Property.integer("channel-session-max-extdata-bufsize", 0);

    /**
     * See {@link org.apache.sshd.server.kex.DHGEXServer}.
     */
    public static final Property<Integer> PROP_DHGEX_SERVER_MIN_KEY
            = Property.integer("dhgex-server-min");

    /**
     * See {@link org.apache.sshd.server.kex.DHGEXServer}.
     */
    public static final Property<Integer> PROP_DHGEX_SERVER_MAX_KEY
            = Property.integer("dhgex-server-max");
    /**
     * Value used by the {@link org.apache.sshd.server.shell.InvertedShellWrapper} to control the &quot;busy-wait&quot;
     * sleep time (millis) on the pumping loop if nothing was pumped - must be <U>positive</U>.
     */
    public static final Property<Duration> PUMP_SLEEP_TIME
            = Property.duration("inverted-shell-wrapper-pump-sleep", Duration.ofMillis(1));

    /**
     * Value used by the {@link org.apache.sshd.server.shell.InvertedShellWrapper} to control copy buffer size.
     */
    public static final Property<Integer> BUFFER_SIZE
            = Property.integer("inverted-shell-wrapper-buffer-size", IoUtils.DEFAULT_COPY_SIZE);

    /**
     * Configuration value for the {@link org.apache.sshd.server.x11.X11ForwardSupport} to control the channel open
     * timeout.
     */
    public static final Property<Duration> X11_OPEN_TIMEOUT
            = Property.duration("x11-fwd-open-timeout", Duration.ofSeconds(30L));

    /**
     * Configuration value for the {@link org.apache.sshd.server.x11.X11ForwardSupport} to control from which X11
     * display number to start looking for a free value.
     */
    public static final Property<Integer> X11_DISPLAY_OFFSET
            = Property.integer("x11-fwd-display-offset", 10);

    /**
     * Configuration value for the {@link org.apache.sshd.server.x11.X11ForwardSupport} to control up to which (but not
     * including) X11 display number to look or a free value.
     */
    public static final Property<Integer> X11_MAX_DISPLAYS
            = Property.integer("x11-fwd-max-display", 1000);

    /**
     * Configuration value for the {@link org.apache.sshd.server.x11.X11ForwardSupport} to control the base port number
     * for the X11 display number socket binding.
     */
    public static final Property<Integer> X11_BASE_PORT
            = Property.integer("x11-fwd-base-port", 6000);

    /**
     * Configuration value for the {@link org.apache.sshd.server.x11.X11ForwardSupport} to control the host used to bind
     * to for the X11 display when looking for a free port.
     */
    public static final Property<String> X11_BIND_HOST
            = Property.string("x11-fwd-bind-host", SshdSocketAddress.LOCALHOST_IPV4);

    /**
     * Configuration value for the {@link org.apache.sshd.server.forward.TcpipServerChannel} to control the higher
     * theshold for the data to be buffered waiting to be sent. If the buffered data size reaches this value, the
     * session will pause reading until the data length goes below the
     * {@link #TCPIP_SERVER_CHANNEL_BUFFER_SIZE_THRESHOLD_LOW} threshold.
     */
    public static final Property<Long> TCPIP_SERVER_CHANNEL_BUFFER_SIZE_THRESHOLD_HIGH
            = Property.long_("tcpip-server-channel-buffer-size-threshold-high", 1024 * 1024);

    /**
     * The lower threshold. If not set, half the higher threshold will be used.
     * 
     * @see #TCPIP_SERVER_CHANNEL_BUFFER_SIZE_THRESHOLD_HIGH
     */
    public static final Property<Long> TCPIP_SERVER_CHANNEL_BUFFER_SIZE_THRESHOLD_LOW
            = Property.long_("tcpip-server-channel-buffer-size-threshold-low");

    private CoreModuleProperties() {
        throw new UnsupportedOperationException("No instance");
    }
}
