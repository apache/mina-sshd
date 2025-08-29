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
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.agent.common.AgentForwardSupport;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.forward.Forwarder;
import org.apache.sshd.common.forward.PortForwardingEventListenerManager;
import org.apache.sshd.common.forward.PortForwardingEventListenerManagerHolder;
import org.apache.sshd.common.future.GlobalRequestFuture;
import org.apache.sshd.common.future.GlobalRequestFuture.ReplyHandler;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.server.x11.X11ForwardSupport;

/**
 * Interface implementing ssh-connection service.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ConnectionService
        extends Service,
        SessionHeartbeatController,
        UnknownChannelReferenceHandlerManager,
        PortForwardingEventListenerManager,
        PortForwardingEventListenerManagerHolder {

    /**
     * Register a newly created channel with a new unique identifier
     *
     * @param  channel     The {@link Channel} to register
     * @return             The assigned id of this channel - a UINT32 represented as a {@code long}
     * @throws IOException If failed to initialize and register the channel
     */
    long registerChannel(Channel channel) throws IOException;

    /**
     * Remove this channel from the list of managed channels
     *
     * @param channel The {@link Channel} instance
     */
    void unregisterChannel(Channel channel);

    /**
     * Retrieve the forwarder instance
     *
     * @return The {@link Forwarder}
     */
    Forwarder getForwarder();

    /**
     * Send a global request and wait for the response, if the request is sent with {@code want-reply = true}.
     *
     * @param  request                         the request name - used mainly for logging and debugging
     * @param  buffer                          the buffer containing the global request
     * @param  timeout                         The number of time units to wait - must be <U>positive</U>
     * @param  unit                            The {@link TimeUnit} to wait for the response
     * @return                                 the return buffer if the request was successful, {@code null} otherwise.
     * @throws IOException                     if an error occurred when encoding or sending the packet
     * @throws java.net.SocketTimeoutException If no response received within specified timeout
     */
    default Buffer request(String request, Buffer buffer, long timeout, TimeUnit unit) throws IOException {
        ValidateUtils.checkTrue(timeout > 0L, "Non-positive timeout requested: %d", timeout);
        return request(request, buffer, TimeUnit.MILLISECONDS.convert(timeout, unit));
    }

    /**
     *
     * Send a global request and wait for the response, if the request is sent with {@code want-reply = true}.
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
     * Send a global request and wait for the response, if the request is sent with {@code want-reply = true}.
     *
     * @param  request                         the request name - used mainly for logging and debugging
     * @param  buffer                          the buffer containing the global request
     * @param  maxWaitMillis                   maximum time in milliseconds to wait for the request to finish - must be
     *                                         <U>positive</U>
     * @return                                 the return buffer if the request was successful, {@code null} otherwise.
     * @throws IOException                     if an error occurred when encoding or sending the packet
     * @throws java.net.SocketTimeoutException If no response received within specified timeout
     */
    Buffer request(String request, Buffer buffer, long maxWaitMillis) throws IOException;

    /**
     * Send a global request and handle the reply asynchronously. If {@code want-reply = true}, pass the received
     * {@link Buffer} to the given {@link ReplyHandler}, which may execute in a different thread.
     *
     * <dl>
     * <dt>want-reply == true &amp;&amp; replyHandler != null</dt>
     * <dd>The returned future is fulfilled with {@code null} when the request was sent, or with an exception if the
     * request could not be sent. The {@code replyHandler} is invoked once the reply is received, with the SSH reply
     * code and the data received.</dd>
     * <dt>want-reply == true &amp;&amp; replyHandler == null</dt>
     * <dd>The returned future is fulfilled with an exception if the request could not be sent, or a failure reply was
     * received. If a success reply was received, the future is fulfilled with the received data buffer.</dd>
     * <dt>want-reply == false</dt>
     * <dd>The returned future is fulfilled with an empty {@link Buffer} when the request was sent, or with an exception
     * if the request could not be sent. If a reply handler is given, it is invoked with that empty buffer. The handler
     * is not invoked if sending the request failed.</dd>
     * </dl>
     *
     * @param  buffer       the {@link Buffer} containing the global request, with the {@code want-reply} flag set as
     *                      appropriate
     * @param  request      the request name
     * @param  replyHandler {@link ReplyHandler} for handling the reply; may be {@code null}
     * @return              Created {@link GlobalRequestFuture}
     * @throws IOException  if an error occurred while encoding or sending the packet
     */
    GlobalRequestFuture request(Buffer buffer, String request, ReplyHandler replyHandler) throws IOException;

    // TODO: remove from interface, it's server side only
    AgentForwardSupport getAgentForwardSupport();

    // TODO: remove from interface, it's server side only
    X11ForwardSupport getX11ForwardSupport();

    boolean isAllowMoreSessions();

    void setAllowMoreSessions(boolean allow);
}
