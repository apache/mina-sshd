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
package org.apache.sshd.common.channel;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.AttributeStore;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.channel.throttle.ChannelStreamWriterResolverManager;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Represents a channel opened over an SSH session - holds information that is common both to server and client
 * channels.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Channel
        extends SessionHolder<Session>,
        ChannelListenerManager,
        PropertyResolver,
        AttributeStore,
        ChannelStreamWriterResolverManager,
        Closeable {
    // Known types of channels
    String CHANNEL_EXEC = "exec";
    String CHANNEL_SHELL = "shell";
    String CHANNEL_SUBSYSTEM = "subsystem";

    /**
     * @return Local channel identifier
     */
    int getId();

    /**
     * @return Remote channel identifier
     */
    int getRecipient();

    Window getLocalWindow();

    Window getRemoteWindow();

    List<RequestHandler<Channel>> getRequestHandlers();

    void addRequestHandler(RequestHandler<Channel> handler);

    default void addRequestHandlers(Collection<? extends RequestHandler<Channel>> handlers) {
        GenericUtils.forEach(handlers, this::addRequestHandler);
    }

    void removeRequestHandler(RequestHandler<Channel> handler);

    default void removeRequestHandlers(Collection<? extends RequestHandler<Channel>> handlers) {
        GenericUtils.forEach(handlers, this::removeRequestHandler);
    }

    /**
     * Invoked when <code>SSH_MSG_CHANNEL_CLOSE</code> received
     *
     * @throws IOException If failed to handle the message
     */
    void handleClose() throws IOException;

    /**
     * Invoked when <code>SSH_MSG_CHANNEL_WINDOW_ADJUST</code> received
     *
     * @param  buffer      The rest of the message data {@link Buffer} after decoding the channel identifiers
     * @throws IOException If failed to handle the message
     */
    void handleWindowAdjust(Buffer buffer) throws IOException;

    /**
     * Invoked when <code>SSH_MSG_CHANNEL_REQUEST</code> received
     *
     * @param  buffer      The rest of the message data {@link Buffer} after decoding the channel identifiers
     * @throws IOException If failed to handle the message
     */
    void handleRequest(Buffer buffer) throws IOException;

    /**
     * Invoked when <code>SSH_MSG_CHANNEL_DATA</code> received
     *
     * @param  buffer      The rest of the message data {@link Buffer} after decoding the channel identifiers
     * @throws IOException If failed to handle the message
     */
    void handleData(Buffer buffer) throws IOException;

    /**
     * Invoked when <code>SSH_MSG_CHANNEL_EXTENDED_DATA</code> received
     *
     * @param  buffer      The rest of the message data {@link Buffer} after decoding the channel identifiers
     * @throws IOException If failed to handle the message
     */
    void handleExtendedData(Buffer buffer) throws IOException;

    /**
     * Invoked when <code>SSH_MSG_CHANNEL_EOF</code> received
     *
     * @throws IOException If failed to handle the message
     */
    void handleEof() throws IOException;

    /**
     * Invoked when <code>SSH_MSG_CHANNEL_SUCCESS</code> received
     *
     * @throws IOException If failed to handle the message
     */
    void handleSuccess() throws IOException;

    /**
     * Invoked when <code>SSH_MSG_CHANNEL_FAILURE</code> received
     *
     * @throws IOException If failed to handle the message
     */
    void handleFailure() throws IOException;

    /**
     * Invoked when the local channel is initial created
     *
     * @param  service     The {@link ConnectionService} through which the channel is initialized
     * @param  session     The {@link Session} associated with the channel
     * @param  id          The locally assigned channel identifier
     * @throws IOException If failed to process the initialization
     */
    void init(ConnectionService service, Session session, int id) throws IOException;

    /**
     * Invoked after being successfully registered by the connection service - should throw a {@link RuntimeException}
     * if not registered
     *
     * @param service    The {@link ConnectionService} through which the channel is registered
     * @param session    The {@link Session} associated with the channel
     * @param id         The locally assigned channel identifier
     * @param registered Whether registration was successful or not
     */
    void handleChannelRegistrationResult(ConnectionService service, Session session, int id, boolean registered);

    /**
     * Called by the connection service to inform the channel that it has bee unregistered.
     *
     * @param service The {@link ConnectionService} through which the channel is unregistered
     */
    void handleChannelUnregistration(ConnectionService service);

    /**
     * @return {@code true} if call to {@link #init(ConnectionService, Session, int)} was successfully completed
     */
    boolean isInitialized();

    /**
     * @return {@code true} if the peer signaled that it will not send any more data
     * @see    <A HREF="https://tools.ietf.org/html/rfc4254#section-5.3">RFC 4254 - section 5.3 -
     *         SSH_MSG_CHANNEL_EOF</A>
     */
    boolean isEofSignalled();

    /**
     * For a server channel, this method will actually open the channel
     *
     * @param  recipient  Recipient identifier
     * @param  rwSize     Read/Write window size ({@code uint32})
     * @param  packetSize Preferred maximum packet size ({@code uint32})
     * @param  buffer     Incoming {@link Buffer} that triggered the call. <B>Note:</B> the buffer's read position is
     *                    exactly <U>after</U> the information that read to this call was decoded
     * @return            An {@link OpenFuture} for the channel open request
     */
    OpenFuture open(int recipient, long rwSize, long packetSize, Buffer buffer);

    /**
     * For a client channel, this method will be called internally by the session when the confirmation has been
     * received.
     *
     * @param  recipient   Recipient identifier
     * @param  rwSize      Read/Write window size ({@code uint32})
     * @param  packetSize  Preferred maximum packet size ({@code uint32})
     * @param  buffer      Incoming {@link Buffer} that triggered the call. <B>Note:</B> the buffer's read position is
     *                     exactly <U>after</U> the information that read to this call was decoded
     * @throws IOException If failed to handle the success
     */
    void handleOpenSuccess(int recipient, long rwSize, long packetSize, Buffer buffer) throws IOException;

    /**
     * For a client channel, this method will be called internally by the session when the server has rejected this
     * channel opening.
     *
     * @param  buffer      Incoming {@link Buffer} that triggered the call. <B>Note:</B> the buffer's read position is
     *                     exactly <U>after</U> the information that read to this call was decoded
     * @throws IOException If failed to handle the success
     */
    void handleOpenFailure(Buffer buffer) throws IOException;

    @Override
    default <T> T resolveAttribute(AttributeRepository.AttributeKey<T> key) {
        return resolveAttribute(this, key);
    }

    /**
     * Attempts to use the channel attribute, if not found then tries the session
     *
     * @param  <T>     The generic attribute type
     * @param  channel The {@link Channel} - ignored if {@code null}
     * @param  key     The attribute key - never {@code null}
     * @return         Associated value - {@code null} if not found
     * @see            #getSession()
     * @see            Session#resolveAttribute(Session, AttributeRepository.AttributeKey)
     */
    static <T> T resolveAttribute(Channel channel, AttributeRepository.AttributeKey<T> key) {
        Objects.requireNonNull(key, "No key");
        if (channel == null) {
            return null;
        }

        T value = channel.getAttribute(key);
        return (value != null) ? value : Session.resolveAttribute(channel.getSession(), key);
    }

    /**
     * Encode and send the given buffer. <B>Note:</B> for session packets the buffer has to have 5 bytes free at the
     * beginning to allow the encoding to take place. Also, the write position of the buffer has to be set to the
     * position of the last byte to write.
     *
     * @param  buffer      the buffer to encode and send. <B>NOTE:</B> the buffer must not be touched until the returned
     *                     write future is completed.
     * @return             An {@code IoWriteFuture} that can be used to check when the packet has actually been sent
     * @throws IOException if an error occurred when encoding or sending the packet
     */
    IoWriteFuture writePacket(Buffer buffer) throws IOException;
}
