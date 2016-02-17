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
package org.apache.sshd.server.channel;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.AbstractChannel;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.server.session.ServerSession;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractServerChannel extends AbstractChannel implements ServerChannel {

    protected final AtomicBoolean exitStatusSent = new AtomicBoolean(false);

    protected AbstractServerChannel() {
        this(Collections.<RequestHandler<Channel>>emptyList());
    }

    protected AbstractServerChannel(Collection<? extends RequestHandler<Channel>> handlers) {
        this("", handlers);
    }

    protected AbstractServerChannel(String discriminator, Collection<? extends RequestHandler<Channel>> handlers) {
        super(discriminator, false, handlers);
    }

    @Override
    public ServerSession getServerSession() {
        return (ServerSession) getSession();
    }

    @Override
    public OpenFuture open(int recipient, int rwSize, int packetSize, Buffer buffer) {
        setRecipient(recipient);

        Session s = getSession();
        FactoryManager manager = ValidateUtils.checkNotNull(s.getFactoryManager(), "No factory manager");
        Window wRemote = getRemoteWindow();
        wRemote.init(rwSize, packetSize, manager.getProperties());
        configureWindow();
        return doInit(buffer);
    }

    @Override
    public void handleOpenSuccess(int recipient, int rwSize, int packetSize, Buffer buffer) throws IOException {
        throw new UnsupportedOperationException("handleOpenSuccess(" + recipient + "," + rwSize + "," + packetSize + ") N/A");
    }

    @Override
    public void handleOpenFailure(Buffer buffer) {
        throw new UnsupportedOperationException("handleOpenFailure() N/A");
    }

    protected OpenFuture doInit(Buffer buffer) {
        ChannelListener listener = getChannelListenerProxy();
        OpenFuture f = new DefaultOpenFuture(this);
        try {
            listener.channelOpenSuccess(this);
            f.setOpened();
        } catch (Throwable t) {
            Throwable e = GenericUtils.peelException(t);
            try {
                listener.channelOpenFailure(this, e);
            } catch (Throwable err) {
                Throwable ignored = GenericUtils.peelException(err);
                log.warn("doInit({}) failed ({}) to inform listener of open failure={}: {}",
                         this, ignored.getClass().getSimpleName(), e.getClass().getSimpleName(), ignored.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("doInit(" + this + ") listener inform failure details", ignored);
                }
                if (log.isTraceEnabled()) {
                    Throwable[] suppressed = ignored.getSuppressed();
                    if (GenericUtils.length(suppressed) > 0) {
                        for (Throwable s : suppressed) {
                            log.trace("doInit(" + this + ") suppressed channel open failure signalling", s);
                        }
                    }
                }
            }
            f.setException(e);
        }

        return f;
    }

    protected void sendExitStatus(int v) throws IOException {
        if (exitStatusSent.getAndSet(true)) {
            if (log.isDebugEnabled()) {
                log.debug("sendExitStatus({}) exit-status={} - already sent", this, v);
            }
            notifyStateChanged("exit-status");   // just in case
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("sendExitStatus({}) SSH_MSG_CHANNEL_REQUEST exit-status={}", this, v);
        }

        Session session = getSession();
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_REQUEST, Long.SIZE);
        buffer.putInt(getRecipient());
        buffer.putString("exit-status");
        buffer.putBoolean(false);   // want-reply - must be FALSE - see https://tools.ietf.org/html/rfc4254 section 6.10
        buffer.putInt(v);
        writePacket(buffer);
        notifyStateChanged("exit-status");
    }
}
