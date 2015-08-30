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
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.channel.ChannelListenerManager;
import org.apache.sshd.common.future.KeyExchangeFuture;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Represents an SSH session
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Session extends SessionListenerManager, ChannelListenerManager, Closeable {

    /**
     * Timeout status.
     */
    enum TimeoutStatus {
        NoTimeout,
        AuthTimeout,
        IdleTimeout
    }

    /**
     * Returns the value of the user-defined attribute of this session.
     *
     * @param <T> The generic attribute type
     * @param key The key of the attribute; must not be {@code null}.
     * @return <tt>null</tt> if there is no attribute with the specified key
     */
    <T> T getAttribute(AttributeKey<T> key);

    /**
     * Sets a user-defined attribute.
     *
     * @param <T>   The generic attribute type
     * @param <E>   The generic value type
     * @param key   The key of the attribute; must not be {@code null}.
     * @param value The value of the attribute; must not be {@code null}.
     * @return The old value of the attribute.  {@code null} if it is new.
     */
    <T, E extends T> T setAttribute(AttributeKey<T> key, E value);

    /**
     * Retrieve the name of the user authenticated on this session
     * or null if the session has not been authenticated yet.
     *
     * @return the user name.
     */
    String getUsername();

    void setUsername(String username);

    /**
     * Retrieve the client version for this session.
     *
     * @return the client version.
     */
    String getClientVersion();

    /**
     * Retrieve the server version for this session.
     *
     * @return the server version.
     */
    String getServerVersion();

    /**
     * @return the {@link FactoryManager} that has created this session, can not be {@code null}
     */
    FactoryManager getFactoryManager();

    /**
     * Retrieve one of the negotiated values during the KEX stage
     *
     * @param paramType The request {@link KexProposalOption} value - ignored
     *                  if {@code null}
     * @return The negotiated parameter value - {@code null} if invalid
     * parameter or no negotiated value
     */
    String getNegotiatedKexParameter(KexProposalOption paramType);

    /**
     * Retrieve a configuration property as an integer
     *
     * @param name         the name of the property
     * @param defaultValue the default value
     * @return the value of the configuration property or the default value if not found
     */
    int getIntProperty(String name, int defaultValue);

    /**
     * Create a new buffer for the specified SSH packet and reserve the needed space
     * (5 bytes) for the packet header.
     *
     * @param cmd the SSH command
     * @return a new buffer ready for write
     */
    Buffer createBuffer(byte cmd);

    /**
     * Create a new buffer for the specified SSH packet and reserve the needed space
     * (5 bytes) for the packet header.
     *
     * @param cmd           the SSH command
     * @param estimatedSize estimated number of bytes the buffer will hold, 0 if unknown.
     * @return a new buffer ready for write
     */
    Buffer createBuffer(byte cmd, int estimatedSize);

    /**
     * Encode and send the given buffer.
     * The buffer has to have 5 bytes free at the beginning to allow the encoding to take place.
     * Also, the write position of the buffer has to be set to the position of the last byte to write.
     *
     * @param buffer the buffer to encode and send
     * @return a future that can be used to check when the packet has actually been sent
     * @throws java.io.IOException if an error occurred when encoding sending the packet
     */
    IoWriteFuture writePacket(Buffer buffer) throws IOException;

    /**
     * Encode and send the given buffer with the specified timeout.
     * If the buffer could not be written before the timeout elapses, the returned
     * {@link org.apache.sshd.common.io.IoWriteFuture} will be set with a
     * {@link java.util.concurrent.TimeoutException} exception to indicate a timeout.
     *
     * @param buffer  the buffer to encode and spend
     * @param timeout the timeout
     * @param unit    the time unit of the timeout parameter
     * @return a future that can be used to check when the packet has actually been sent
     * @throws java.io.IOException if an error occurred when encoding sending the packet
     */
    IoWriteFuture writePacket(Buffer buffer, long timeout, TimeUnit unit) throws IOException;

    /**
     * Send a global request and wait for the response.
     * This must only be used when sending a SSH_MSG_GLOBAL_REQUEST with a result expected,
     * else it will wait forever.
     *
     * @param buffer the buffer containing the global request
     * @return the return buffer if the request was successful, {@code null} otherwise.
     * @throws java.io.IOException if an error occurred when encoding sending the packet
     */
    Buffer request(Buffer buffer) throws IOException;

    /**
     * Handle any exceptions that occured on this session.
     * The session will be closed and a disconnect packet will be
     * sent before if the given exception is an
     * {@link org.apache.sshd.common.SshException}.
     *
     * @param t the exception to process
     */
    void exceptionCaught(Throwable t);

    /**
     * Initiate a new key exchange.
     *
     * @return An {@link KeyExchangeFuture} for awaiting the completion of the exchange
     * @throws IOException If failed to negotiate keys
     */
    KeyExchangeFuture reExchangeKeys() throws IOException;

    /**
     * Get the service of the specified type.
     * If the service is not of the specified class,
     * an IllegalStateException will be thrown.
     *
     * @param <T>   The generic service type
     * @param clazz The service class
     * @return The service instance
     * @throws IllegalStateException If failed to find a matching service
     */
    <T extends Service> T getService(Class<T> clazz);

    /**
     * @return the {@link IoSession} associated to this session
     */
    IoSession getIoSession();

    /**
     * <P>
     * Type safe key for storage within the user attributes of {@link org.apache.sshd.common.session.AbstractSession}.
     * Typically it is used as a static variable that is shared between the producer
     * and the consumer. To further restrict access the setting or getting it from
     * the Session you can add static get and set methods, e.g:
     * </P>
     *
     * <pre>
     * private static final AttributeKey&lt;MyValue&gt; MY_KEY = new AttributeKey&lt;MyValue&gt;();
     *
     * public static MyValue getMyValue(Session s) {
     *   return s.getAttribute(MY_KEY);
     * }
     *
     * private void setMyValue(Session s, MyValue value) {
     *   s.setAttribute(MY_KEY, value);
     * }
     * </pre>
     *
     * @param <T> type of value stored in the attribute.
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    public class AttributeKey<T> {
        public AttributeKey() {
            super();
        }
    }

    void resetIdleTimeout();

    /**
     * Check if timeout has occurred.
     *
     * @return the timeout status, never {@code null}
     */
    TimeoutStatus getTimeoutStatus();

    /**
     * @return Timeout value in milliseconds for authentication stage
     */
    long getAuthTimeout();

    /**
     * @return Timeout value in milliseconds for communication
     */
    long getIdleTimeout();

    boolean isAuthenticated();

    void setAuthenticated() throws IOException;

    byte[] getSessionId();

    KeyExchange getKex();

    /**
     * Send a disconnect packet with the given reason and message.
     * Once the packet has been sent, the session will be closed
     * asynchronously.
     *
     * @param reason the reason code for this disconnect
     * @param msg    the text message
     * @throws IOException if an error occurred sending the packet
     */
    void disconnect(int reason, String msg) throws IOException;

    /**
     * @param name Service name
     * @throws Exception If failed to start it
     */
    void startService(String name) throws Exception;
}
