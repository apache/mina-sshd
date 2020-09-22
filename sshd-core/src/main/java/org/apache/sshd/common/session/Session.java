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
package org.apache.sshd.common.session;

import java.io.IOException;
import java.net.SocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerHolder;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.auth.MutableUserHolder;
import org.apache.sshd.common.channel.ChannelListenerManager;
import org.apache.sshd.common.channel.throttle.ChannelStreamWriterResolverManager;
import org.apache.sshd.common.forward.PortForwardingEventListenerManager;
import org.apache.sshd.common.forward.PortForwardingInformationProvider;
import org.apache.sshd.common.future.KeyExchangeFuture;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexFactoryManager;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.session.helpers.TimeoutIndicator;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Represents an SSH session. <B>Note:</B> the associated username for the session may be {@code null}/empty if the
 * session is not yet authenticated
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Session
        extends SessionContext,
        MutableUserHolder,
        KexFactoryManager,
        SessionListenerManager,
        ReservedSessionMessagesManager,
        SessionDisconnectHandlerManager,
        ChannelListenerManager,
        ChannelStreamWriterResolverManager,
        PortForwardingEventListenerManager,
        UnknownChannelReferenceHandlerManager,
        FactoryManagerHolder,
        PortForwardingInformationProvider {

    /**
     * Create a new buffer for the specified SSH packet and reserve the needed space (5 bytes) for the packet header.
     *
     * @param  cmd the SSH command
     * @return     a new buffer (of unknown size) ready for write
     * @see        #createBuffer(byte, int)
     */
    default Buffer createBuffer(byte cmd) {
        return createBuffer(cmd, 0);
    }

    /**
     * Create a new buffer for the specified SSH packet and reserve the needed space (5 bytes) for the packet header.
     *
     * @param  cmd           The SSH command to initialize the buffer with
     * @param  estimatedSize Estimated number of bytes the buffer will hold, 0 if unknown.
     * @return               a new buffer ready for write
     * @see                  #prepareBuffer(byte, Buffer)
     */
    Buffer createBuffer(byte cmd, int estimatedSize);

    /**
     * Prepare a new &quot;clean&quot; buffer while reserving the needed space (5 bytes) for the packet header.
     *
     * @param  cmd    The SSH command to initialize the buffer with
     * @param  buffer The {@link Buffer} instance to initialize
     * @return        The initialized buffer
     */
    Buffer prepareBuffer(byte cmd, Buffer buffer);

    /**
     * Sends an {@code SSH_MSG_DEBUG} to the peer session
     *
     * @param  display     {@code true} if OK to display the message at the peer as-is
     * @param  msg         The message object whose {@code toString()} value to be used - if {@code null} then the
     *                     &quot;null&quot; string is sent
     * @param  lang        The language - {@code null}/empty if some pre-agreed default is used
     * @return             An {@code IoWriteFuture} that can be used to check when the packet has actually been sent
     * @throws IOException if an error occurred when encoding or sending the packet
     * @see                <A HREF="https://tools.ietf.org/html/rfc4253#section-11.3">RFC 4253 - section 11.3</A>
     */
    IoWriteFuture sendDebugMessage(boolean display, Object msg, String lang) throws IOException;

    /**
     * Sends an {@code SSH_MSG_IGNORE} to the peer session
     *
     * @param  data        The message data
     * @return             An {@code IoWriteFuture} that can be used to check when the packet has actually been sent
     * @throws IOException if an error occurred when encoding or sending the packet
     * @see                <A HREF="https://tools.ietf.org/html/rfc4253#section-11.2">RFC 4253 - section 11.2</A>
     */
    IoWriteFuture sendIgnoreMessage(byte... data) throws IOException;

    /**
     * Encode and send the given buffer. The buffer has to have 5 bytes free at the beginning to allow the encoding to
     * take place. Also, the write position of the buffer has to be set to the position of the last byte to write.
     *
     * @param  buffer      the buffer to encode and send
     * @return             An {@code IoWriteFuture} that can be used to check when the packet has actually been sent
     * @throws IOException if an error occurred when encoding sending the packet
     */
    IoWriteFuture writePacket(Buffer buffer) throws IOException;

    /**
     * Encode and send the given buffer with the specified timeout. If the buffer could not be written before the
     * timeout elapses, the returned {@link org.apache.sshd.common.io.IoWriteFuture} will be set with a
     * {@link java.util.concurrent.TimeoutException} exception to indicate a timeout.
     *
     * @param  buffer      the buffer to encode and spend
     * @param  timeout     the (never {@code null}) timeout value - its {@link Duration#toMillis() milliseconds} value
     *                     will be used
     * @return             a future that can be used to check when the packet has actually been sent
     * @throws IOException if an error occurred when encoding or sending the packet
     * @see                #writePacket(Buffer, long)
     */
    default IoWriteFuture writePacket(Buffer buffer, Duration timeout) throws IOException {
        Objects.requireNonNull(timeout, "No timeout was specified");
        return writePacket(buffer, timeout.toMillis());
    }

    /**
     * Encode and send the given buffer with the specified timeout. If the buffer could not be written before the
     * timeout elapses, the returned {@link org.apache.sshd.common.io.IoWriteFuture} will be set with a
     * {@link java.util.concurrent.TimeoutException} exception to indicate a timeout.
     *
     * @param  buffer        the buffer to encode and spend
     * @param  maxWaitMillis the timeout in milliseconds
     * @return               a future that can be used to check when the packet has actually been sent
     * @throws IOException   if an error occurred when encoding or sending the packet
     */
    default IoWriteFuture writePacket(Buffer buffer, long maxWaitMillis) throws IOException {
        return writePacket(buffer, maxWaitMillis, TimeUnit.MILLISECONDS);
    }

    /**
     * Encode and send the given buffer with the specified timeout. If the buffer could not be written before the
     * timeout elapses, the returned {@link org.apache.sshd.common.io.IoWriteFuture} will be set with a
     * {@link java.util.concurrent.TimeoutException} exception to indicate a timeout.
     *
     * @param  buffer      the buffer to encode and spend
     * @param  timeout     the timeout
     * @param  unit        the time unit of the timeout parameter
     * @return             a future that can be used to check when the packet has actually been sent
     * @throws IOException if an error occurred when encoding or sending the packet
     */
    IoWriteFuture writePacket(Buffer buffer, long timeout, TimeUnit unit) throws IOException;

    /**
     * Send a global request and wait for the response. This must only be used when sending a
     * {@code SSH_MSG_GLOBAL_REQUEST} with a result expected, else it will time out
     *
     * @param  request                         the request name - used mainly for logging and debugging
     * @param  buffer                          the buffer containing the global request
     * @param  timeout                         The number of time units to wait - must be <U>positive</U>
     * @param  unit                            The {@link TimeUnit} to wait for the response
     * @return                                 the return buffer if the request was successful, {@code null} otherwise.
     * @throws IOException                     if an error occurred when encoding or sending the packet
     * @throws java.net.SocketTimeoutException If no response received within specified timeout
     */
    default Buffer request(
            String request, Buffer buffer, long timeout, TimeUnit unit)
            throws IOException {
        ValidateUtils.checkTrue(timeout > 0L, "Non-positive timeout requested: %d", timeout);
        return request(request, buffer, TimeUnit.MILLISECONDS.convert(timeout, unit));
    }

    /**
     *
     * Send a global request and wait for the response. This must only be used when sending a
     * {@code SSH_MSG_GLOBAL_REQUEST} with a result expected, else it will time out
     *
     * @param  request                         the request name - used mainly for logging and debugging
     * @param  buffer                          the buffer containing the global request
     * @param  timeout                         The (never {@code null}) timeout to wait - its milliseconds value is used
     * @return                                 the return buffer if the request was successful, {@code null} otherwise.
     * @throws IOException                     if an error occurred when encoding or sending the packet
     * @throws java.net.SocketTimeoutException If no response received within specified timeout
     */
    default Buffer request(String request, Buffer buffer, Duration timeout) throws IOException {
        Objects.requireNonNull(timeout, "No timeout specified");
        return request(request, buffer, timeout.toMillis());
    }

    /**
     * Send a global request and wait for the response. This must only be used when sending a
     * {@code SSH_MSG_GLOBAL_REQUEST} with a result expected, else it will time out
     *
     * @param  request                         the request name - used mainly for logging and debugging
     * @param  buffer                          the buffer containing the global request
     * @param  maxWaitMillis                   Max. time to wait for response (millis) - must be <U>positive</U>
     * @return                                 the return buffer if the request was successful, {@code null} otherwise.
     * @throws IOException                     if an error occurred when encoding or sending the packet
     * @throws java.net.SocketTimeoutException If no response received within specified timeout
     */
    Buffer request(String request, Buffer buffer, long maxWaitMillis) throws IOException;

    /**
     * Handle any exceptions that occurred on this session. The session will be closed and a disconnect packet will be
     * sent before if the given exception is an {@link org.apache.sshd.common.SshException} with a positive error code
     *
     * @param t the exception to process
     */
    void exceptionCaught(Throwable t);

    /**
     * Initiate a new key exchange.
     *
     * @return             A {@link KeyExchangeFuture} for awaiting the completion of the exchange
     * @throws IOException If failed to request keys re-negotiation
     */
    KeyExchangeFuture reExchangeKeys() throws IOException;

    /**
     * Get the service of the specified type. If the service is not of the specified class, an IllegalStateException
     * will be thrown.
     *
     * @param  <T>                   The generic {@link Service} type
     * @param  clazz                 The service class
     * @return                       The service instance
     * @throws IllegalStateException If failed to find a matching service
     */
    <T extends Service> T getService(Class<T> clazz);

    /**
     * @return The {@link IoSession} associated to this session
     */
    IoSession getIoSession();

    @Override
    default SocketAddress getLocalAddress() {
        IoSession s = getIoSession();
        return (s == null) ? null : s.getLocalAddress();
    }

    @Override
    default SocketAddress getRemoteAddress() {
        IoSession s = getIoSession();
        return (s == null) ? null : s.getRemoteAddress();
    }

    /**
     * Check if timeout has occurred.
     *
     * @return the timeout status - never {@code null}
     */
    TimeoutIndicator getTimeoutStatus();

    /**
     * @return Timeout value in milliseconds for communication
     */
    Duration getIdleTimeout();

    /**
     * @return The timestamp value (milliseconds since EPOCH) when timer was started
     */
    Instant getIdleTimeoutStart();

    /**
     * Re-start idle timeout timer
     *
     * @return The timestamp value (milliseconds since EPOCH) when timer was started
     * @see    #getIdleTimeoutStart()
     */
    Instant resetIdleTimeout();

    /**
     * @return Timeout value in milliseconds for authentication stage
     */
    Duration getAuthTimeout();

    /**
     * @return The timestamp value (milliseconds since EPOCH) when timer was started
     */
    Instant getAuthTimeoutStart();

    /**
     * Re-start the authentication timeout timer
     *
     * @return The timestamp value (milliseconds since EPOCH) when timer was started
     * @see    #getAuthTimeoutStart()
     */
    Instant resetAuthTimeout();

    void setAuthenticated() throws IOException;

    /**
     * @return The current {@link KeyExchange} in progress - {@code null} if KEX not started or successfully completed
     */
    KeyExchange getKex();

    /**
     * Send a disconnect packet with the given reason and message. Once the packet has been sent, the session will be
     * closed asynchronously.
     *
     * @param  reason      the reason code for this disconnect
     * @param  msg         the text message
     * @throws IOException if an error occurred sending the packet
     */
    void disconnect(int reason, String msg) throws IOException;

    /**
     * @param  name      Service name
     * @param  buffer    Extra information provided when the service start request was received
     * @throws Exception If failed to start it
     */
    void startService(String name, Buffer buffer) throws Exception;

    @Override
    default <T> T resolveAttribute(AttributeRepository.AttributeKey<T> key) {
        return resolveAttribute(this, key);
    }

    /**
     * Attempts to use the session's attribute, if not found then tries the factory manager
     *
     * @param  <T>     The generic attribute type
     * @param  session The {@link Session} - ignored if {@code null}
     * @param  key     The attribute key - never {@code null}
     * @return         Associated value - {@code null} if not found
     * @see            Session#getFactoryManager()
     * @see            FactoryManager#resolveAttribute(FactoryManager, AttributeRepository.AttributeKey)
     */
    static <T> T resolveAttribute(Session session, AttributeRepository.AttributeKey<T> key) {
        Objects.requireNonNull(key, "No key");
        if (session == null) {
            return null;
        }

        T value = session.getAttribute(key);
        return (value != null) ? value : FactoryManager.resolveAttribute(session.getFactoryManager(), key);
    }
}
