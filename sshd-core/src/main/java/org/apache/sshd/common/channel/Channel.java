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

import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.AttributeStore;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Represents a channel opened over an SSH session - holds information that is
 * common both to server and client channels.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Channel
        extends ChannelListenerManager,
                PropertyResolver,
                AttributeStore,
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

    /**
     * @return The channel's underlying {@link Session}
     */
    Session getSession();

    Window getLocalWindow();

    Window getRemoteWindow();

    /**
     * Invoked when <code>SSH_MSG_CHANNEL_CLOSE</code> received
     *
     * @throws IOException If failed to handle the message
     */
    void handleClose() throws IOException;

    /**
     * Invoked when <code>SSH_MSG_CHANNEL_WINDOW_ADJUST</code> received
     *
     * @param buffer The rest of the message data {@link Buffer} after
     * decoding the channel identifiers
     * @throws IOException If failed to handle the message
     */
    void handleWindowAdjust(Buffer buffer) throws IOException;

    /**
     * Invoked when <code>SSH_MSG_CHANNEL_REQUEST</code> received
     *
     * @param buffer The rest of the message data {@link Buffer} after
     * decoding the channel identifiers
     * @throws IOException If failed to handle the message
     */
    void handleRequest(Buffer buffer) throws IOException;

    /**
     * Invoked when <code>SSH_MSG_CHANNEL_DATA</code> received
     *
     * @param buffer The rest of the message data {@link Buffer} after
     * decoding the channel identifiers
     * @throws IOException If failed to handle the message
     */
    void handleData(Buffer buffer) throws IOException;

    /**
     * Invoked when <code>SSH_MSG_CHANNEL_EXTENDED_DATA</code> received
     *
     * @param buffer The rest of the message data {@link Buffer} after
     * decoding the channel identifiers
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
     * @param service The {@link ConnectionService} through which the channel is initialized
     * @param session The {@link Session} associated with the channel
     * @param id The locally assigned channel identifier
     * @throws IOException If failed to process the initialization
     */
    void init(ConnectionService service, Session session, int id) throws IOException;

    /**
     * @return {@code true} if call to {@link #init(ConnectionService, Session, int)} was
     * successfully completed
     */
    boolean isInitialized();

    /**
     * @return {@code true} if the peer signaled that it will not send any
     * more data
     * @see <A HREF="https://www.ietf.org/rfc/rfc4254.txt">RFC 4254 - section 5.3 - SSH_MSG_CHANNEL_EOE</A>
     */
    boolean isEofSignalled();

    /**
     * For a server channel, this method will actually open the channel
     *
     * @param recipient  Recipient identifier
     * @param rwSize     Read/Write window size
     * @param packetSize Preferred maximum packet size
     * @param buffer     Incoming {@link Buffer} that triggered the call.
     *                   <B>Note:</B> the buffer's read position is exactly
     *                   <U>after</U> the information that read to this call
     *                   was decoded
     * @return An {@link OpenFuture} for the channel open request
     */
    OpenFuture open(int recipient, int rwSize, int packetSize, Buffer buffer);

    /**
     * For a client channel, this method will be called internally by the
     * session when the confirmation has been received.
     *
     * @param recipient  Recipient identifier
     * @param rwSize     Read/Write window size
     * @param packetSize Preferred maximum packet size
     * @param buffer     Incoming {@link Buffer} that triggered the call.
     *                   <B>Note:</B> the buffer's read position is exactly
     *                   <U>after</U> the information that read to this call
     *                   was decoded
     * @throws IOException If failed to handle the success
     */
    void handleOpenSuccess(int recipient, int rwSize, int packetSize, Buffer buffer) throws IOException;

    /**
     * For a client channel, this method will be called internally by the
     * session when the server has rejected this channel opening.
     *
     * @param buffer     Incoming {@link Buffer} that triggered the call.
     *                   <B>Note:</B> the buffer's read position is exactly
     *                   <U>after</U> the information that read to this call
     *                   was decoded
     * @throws IOException If failed to handle the success
     */
    void handleOpenFailure(Buffer buffer) throws IOException;
}
