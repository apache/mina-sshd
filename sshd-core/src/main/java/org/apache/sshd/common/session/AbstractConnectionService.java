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
package org.apache.sshd.common.session;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.agent.common.AgentForwardSupport;
import org.apache.sshd.client.channel.AbstractClientChannel;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.TcpipForwarder;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.x11.X11ForwardSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base implementation of ConnectionService.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractConnectionService implements ConnectionService {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    /** Map of channels keyed by the identifier */
    protected final Map<Integer, Channel> channels = new ConcurrentHashMap<Integer, Channel>();
    /** Next channel identifier */
    protected static final AtomicInteger nextChannelId = new AtomicInteger(100);

    protected final Session session;

    /** The tcpip forwarder */
    protected final TcpipForwarder tcpipForwarder;
    protected final AgentForwardSupport agentForward;
    protected final X11ForwardSupport x11Forward;
    protected final CloseFuture closeFuture;
    protected volatile boolean closing;

    protected AbstractConnectionService(Session session) {
        this.session = session;
        agentForward = new AgentForwardSupport(this);
        x11Forward = new X11ForwardSupport(this);
        tcpipForwarder = session.getFactoryManager().getTcpipForwarderFactory().create(this);
        closeFuture = new DefaultCloseFuture(getSession().getLock());
    }

    public AbstractSession getSession() {
        return (AbstractSession) session;
    }

    public void start() {
    }

    public TcpipForwarder getTcpipForwarder() {
        return tcpipForwarder;
    }

    public CloseFuture close(boolean immediately) {
        tcpipForwarder.close();
        agentForward.close();
        x11Forward.close();
        synchronized (getSession().getLock()) {
            if (!closing) {
                try {
                    closing = true;
                    log.debug("Closing session");
                    List<Channel> channelToClose = new ArrayList<Channel>(channels.values());
                    if (channelToClose.size() > 0) {
                        final AtomicInteger latch = new AtomicInteger(channelToClose.size());
                        for (Channel channel : channelToClose) {
                            log.debug("Closing channel {}", channel.getId());
                            channel.close(immediately).addListener(new SshFutureListener() {
                                public void operationComplete(SshFuture sshFuture) {
                                    if (latch.decrementAndGet() == 0) {
                                        closeFuture.setClosed();
                                    }
                                }
                            });
                        }
                    } else {
                        closeFuture.setClosed();
                    }
                } catch (Throwable t) {
                    log.warn("Error closing session", t);
                }
            }
            return closeFuture;
        }
    }

    protected int getNextChannelId() {
        return nextChannelId.incrementAndGet();
    }

    /**
     * Register a newly created channel with a new unique identifier
     *
     * @param channel the channel to register
     * @return the id of this channel
     * @throws Exception
     */
    public int registerChannel(Channel channel) throws IOException {
        int channelId = getNextChannelId();
        channel.init(this, session, channelId);
        channels.put(channelId, channel);
        return channelId;
    }

    /**
     * Remove this channel from the list of managed channels
     *
     * @param channel the channel
     */
    public void unregisterChannel(Channel channel) {
        channels.remove(channel.getId());
    }

    public void channelOpenConfirmation(Buffer buffer) throws IOException {
        Channel channel = getChannel(buffer);
        log.debug("Received SSH_MSG_CHANNEL_OPEN_CONFIRMATION on channel {}", channel.getId());
        int recipient = buffer.getInt();
        int rwsize = buffer.getInt();
        int rmpsize = buffer.getInt();
        channel.handleOpenSuccess(recipient, rwsize, rmpsize, buffer);
    }

    public void channelOpenFailure(Buffer buffer) throws IOException {
        AbstractClientChannel channel = (AbstractClientChannel) getChannel(buffer);
        log.debug("Received SSH_MSG_CHANNEL_OPEN_FAILURE on channel {}", channel.getId());
        channels.remove(channel.getId());
        channel.handleOpenFailure(buffer);
    }

    /**
     * Process incoming data on a channel
     *
     * @param buffer the buffer containing the data
     * @throws IOException if an error occurs
     */
    public void channelData(Buffer buffer) throws IOException {
        Channel channel = getChannel(buffer);
        channel.handleData(buffer);
    }

    /**
     * Process incoming extended data on a channel
     *
     * @param buffer the buffer containing the data
     * @throws IOException if an error occurs
     */
    public void channelExtendedData(Buffer buffer) throws IOException {
        Channel channel = getChannel(buffer);
        channel.handleExtendedData(buffer);
    }

    /**
     * Process a window adjust packet on a channel
     *
     * @param buffer the buffer containing the window adjustement parameters
     * @throws IOException if an error occurs
     */
    public void channelWindowAdjust(Buffer buffer) throws IOException {
        try {
            Channel channel = getChannel(buffer);
            channel.handleWindowAdjust(buffer);
        } catch (SshException e) {
            log.info(e.getMessage());
        }
    }

    /**
     * Process end of file on a channel
     *
     * @param buffer the buffer containing the packet
     * @throws IOException if an error occurs
     */
    public void channelEof(Buffer buffer) throws IOException {
        Channel channel = getChannel(buffer);
        channel.handleEof();
    }

    /**
     * Close a channel due to a close packet received
     *
     * @param buffer the buffer containing the packet
     * @throws IOException if an error occurs
     */
    public void channelClose(Buffer buffer) throws IOException {
        Channel channel = getChannel(buffer);
        channel.handleClose();
        unregisterChannel(channel);
    }

    /**
     * Service a request on a channel
     *
     * @param buffer the buffer containing the request
     * @throws IOException if an error occurs
     */
    public void channelRequest(Buffer buffer) throws IOException {
        Channel channel = getChannel(buffer);
        String type = buffer.getString();
        boolean wantReply = buffer.getBoolean();
        boolean success = channel.handleRequest(type, buffer);
        if (wantReply) {
            Buffer replyBuffer = session.createBuffer(
                    success ? SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS
                            : SshConstants.Message.SSH_MSG_CHANNEL_FAILURE, 0);
            replyBuffer.putInt(channel.getRecipient());
            session.writePacket(replyBuffer);
        }
    }

    /**
     * Process a failure on a channel
     *
     * @param buffer the buffer containing the packet
     * @throws IOException if an error occurs
     */
    public void channelFailure(Buffer buffer) throws IOException {
        Channel channel = getChannel(buffer);
        channel.handleFailure();
    }

    /**
     * Retrieve the channel designated by the given packet
     *
     * @param buffer the incoming packet
     * @return the target channel
     * @throws IOException if the channel does not exists
     */
    protected Channel getChannel(Buffer buffer) throws IOException {
        int recipient = buffer.getInt();
        Channel channel = channels.get(recipient);
        if (channel == null) {
            buffer.rpos(buffer.rpos() - 5);
            SshConstants.Message cmd = buffer.getCommand();
            throw new SshException("Received " + cmd + " on unknown channel " + recipient);
        }
        return channel;
    }

}
