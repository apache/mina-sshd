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
package org.apache.sshd.client.channel;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.channel.exit.ExitSignalChannelRequestHandler;
import org.apache.sshd.client.channel.exit.ExitStatusChannelRequestHandler;
import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.AbstractChannel;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelAsyncInputStream;
import org.apache.sshd.common.channel.ChannelAsyncOutputStream;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.io.IoInputStream;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.EventNotifier;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractClientChannel extends AbstractChannel implements ClientChannel {

    protected final AtomicBoolean opened = new AtomicBoolean();
    protected final String type;

    protected Streaming streaming;

    protected ChannelAsyncOutputStream asyncIn;
    protected ChannelAsyncInputStream asyncOut;
    protected ChannelAsyncInputStream asyncErr;

    protected InputStream in;
    protected OutputStream invertedIn;
    protected OutputStream out;
    protected InputStream invertedOut;
    protected OutputStream err;
    protected InputStream invertedErr;
    protected final AtomicReference<Integer> exitStatusHolder = new AtomicReference<>(null);
    protected final AtomicReference<String> exitSignalHolder = new AtomicReference<>(null);
    protected int openFailureReason;
    protected String openFailureMsg;
    protected String openFailureLang;
    protected OpenFuture openFuture;

    protected AbstractClientChannel(String type) {
        this(type, Collections.<RequestHandler<Channel>>emptyList());
    }

    protected AbstractClientChannel(String type, Collection<? extends RequestHandler<Channel>> handlers) {
        super(true, handlers);
        this.type = ValidateUtils.checkNotNullAndNotEmpty(type, "No channel type specified");
        this.streaming = Streaming.Sync;

        addChannelSignalRequestHandlers(new EventNotifier<String>() {
            @SuppressWarnings("synthetic-access")
            @Override
            public void notifyEvent(String event) throws Exception {
                if (log.isDebugEnabled()) {
                    log.debug("notifyEvent({}): {}", AbstractClientChannel.this, event);
                }
                notifyStateChanged(event);
            }
        });
    }

    protected void addChannelSignalRequestHandlers(EventNotifier<String> notifier) {
        addRequestHandler(new ExitStatusChannelRequestHandler(exitStatusHolder, notifier));
        addRequestHandler(new ExitSignalChannelRequestHandler(exitSignalHolder, notifier));
    }

    @Override
    public Streaming getStreaming() {
        return streaming;
    }

    @Override
    public void setStreaming(Streaming streaming) {
        this.streaming = streaming;
    }

    @Override
    public IoOutputStream getAsyncIn() {
        return asyncIn;
    }

    @Override
    public IoInputStream getAsyncOut() {
        return asyncOut;
    }

    @Override
    public IoInputStream getAsyncErr() {
        return asyncErr;
    }

    @Override
    public OutputStream getInvertedIn() {
        return invertedIn;
    }

    public InputStream getIn() {
        return in;
    }

    @Override
    public void setIn(InputStream in) {
        this.in = in;
    }

    @Override
    public InputStream getInvertedOut() {
        return invertedOut;
    }

    public OutputStream getOut() {
        return out;
    }

    @Override
    public void setOut(OutputStream out) {
        this.out = out;
    }

    @Override
    public InputStream getInvertedErr() {
        return invertedErr;
    }

    public OutputStream getErr() {
        return err;
    }

    @Override
    public void setErr(OutputStream err) {
        this.err = err;
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder()
                .when(openFuture)
                .run(new Runnable() {
                    @SuppressWarnings("synthetic-access")
                    @Override
                    public void run() {
                        // If the channel has not been opened yet,
                        // skip the SSH_MSG_CHANNEL_CLOSE exchange
                        if (openFuture == null) {
                            gracefulFuture.setClosed();
                        }
                        // Close inverted streams after
                        // If the inverted stream is closed before, there's a small time window
                        // in which we have:
                        //    ChannePipedInputStream#closed = true
                        //    ChannePipedInputStream#writerClosed = false
                        // which leads to an IOException("Pipe closed") when reading.
                        IoUtils.closeQuietly(in, out, err);
                        IoUtils.closeQuietly(invertedIn, invertedOut, invertedErr);
                    }
                })
                .parallel(asyncIn, asyncOut, asyncErr)
                .close(new GracefulChannelCloseable())
                .build();
    }

    @Override
    public Set<ClientChannelEvent> waitFor(Collection<ClientChannelEvent> mask, long timeout) {
        ValidateUtils.checkNotNull(mask, "No mask specified");
        long t = 0;
        synchronized (lock) {
            for (Set<ClientChannelEvent> cond = EnumSet.noneOf(ClientChannelEvent.class);; cond.clear()) {
                updateCurrentChannelState(cond);
                if (log.isDebugEnabled()) {
                    if (cond.contains(ClientChannelEvent.EXIT_STATUS)) {
                        log.debug("waitFor({}) mask={} - exit status={}", this, mask, exitStatusHolder);
                    }
                    if (cond.contains(ClientChannelEvent.EXIT_SIGNAL)) {
                        log.debug("waitFor({}) mask={} - exit signal={}", this, mask, exitSignalHolder);
                    }
                }

                boolean nothingInCommon = Collections.disjoint(mask, cond);
                if (!nothingInCommon) {
                    if (log.isTraceEnabled()) {
                        log.trace("WaitFor call returning on channel {}, mask={}, cond={}", this, mask, cond);
                    }
                    return cond;
                }

                if (timeout > 0L) {
                    if (t == 0L) {
                        t = System.currentTimeMillis() + timeout;
                    } else {
                        timeout = t - System.currentTimeMillis();
                        if (timeout <= 0L) {
                            if (log.isTraceEnabled()) {
                                log.trace("WaitFor call timeout on channel {}, mask={}", this, mask);
                            }
                            cond.add(ClientChannelEvent.TIMEOUT);
                            return cond;
                        }
                    }
                }

                if (log.isTraceEnabled()) {
                    log.trace("Waiting {} millis for lock on channel {}, mask={}, cond={}", timeout, this, mask, cond);
                }

                long nanoStart = System.nanoTime();
                try {
                    if (timeout > 0L) {
                        lock.wait(timeout);
                    } else {
                        lock.wait();
                    }

                    long nanoEnd = System.nanoTime();
                    long nanoDuration = nanoEnd - nanoStart;
                    if (log.isTraceEnabled()) {
                        log.trace("Lock notified on channel {} after {} nanos", this, nanoDuration);
                    }
                } catch (InterruptedException e) {
                    long nanoEnd = System.nanoTime();
                    long nanoDuration = nanoEnd - nanoStart;
                    if (log.isTraceEnabled()) {
                        log.trace("waitFor({}) mask={} - ignoring interrupted exception after {} nanos", this, mask, nanoDuration);
                    }
                }
            }
        }
    }

    @Override
    public Set<ClientChannelEvent> getChannelState() {
        Set<ClientChannelEvent> cond = EnumSet.noneOf(ClientChannelEvent.class);
        synchronized (lock) {
            return updateCurrentChannelState(cond);
        }
    }

    // NOTE: assumed to be called under lock
    protected <C extends Collection<ClientChannelEvent>> C updateCurrentChannelState(C state) {
        if ((openFuture != null) && openFuture.isOpened()) {
            state.add(ClientChannelEvent.OPENED);
        }
        if (closeFuture.isClosed()) {
            state.add(ClientChannelEvent.CLOSED);
        }
        if (isEofSignalled()) {
            state.add(ClientChannelEvent.EOF);
        }
        if (exitStatusHolder.get() != null) {
            state.add(ClientChannelEvent.EXIT_STATUS);
        }
        if (exitSignalHolder.get() != null) {
            state.add(ClientChannelEvent.EXIT_SIGNAL);
        }

        return state;
    }

    @Override
    public synchronized OpenFuture open() throws IOException {
        if (isClosing()) {
            throw new SshException("Session has been closed");
        }

        openFuture = new DefaultOpenFuture(lock);
        if (log.isDebugEnabled()) {
            log.debug("open({}) Send SSH_MSG_CHANNEL_OPEN - type={}", this, type);
        }

        Session session = getSession();
        Window wLocal = getLocalWindow();
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_OPEN, type.length() + Integer.SIZE);
        buffer.putString(type);
        buffer.putInt(getId());
        buffer.putInt(wLocal.getSize());
        buffer.putInt(wLocal.getPacketSize());
        writePacket(buffer);
        return openFuture;
    }

    @Override
    public OpenFuture open(int recipient, int rwSize, int packetSize, Buffer buffer) {
        throw new UnsupportedOperationException("open(" + recipient + "," + rwSize + "," + packetSize + ") N/A");
    }

    @Override
    public void handleOpenSuccess(int recipient, int rwSize, int packetSize, Buffer buffer) {
        setRecipient(recipient);

        Session session = getSession();
        FactoryManager manager = ValidateUtils.checkNotNull(session.getFactoryManager(), "No factory manager");
        Window wRemote = getRemoteWindow();
        wRemote.init(rwSize, packetSize, manager.getProperties());

        ChannelListener listener = getChannelListenerProxy();
        String changeEvent = "SSH_MSG_CHANNEL_OPEN_CONFIRMATION";
        try {
            doOpen();

            listener.channelOpenSuccess(this);
            this.opened.set(true);
            this.openFuture.setOpened();
        } catch (Throwable t) {
            Throwable e = GenericUtils.peelException(t);
            changeEvent = e.getClass().getName();
            try {
                listener.channelOpenFailure(this, e);
            } catch (Throwable err) {
                Throwable ignored = GenericUtils.peelException(err);
                log.warn("handleOpenSuccess({}) failed ({}) to inform listener of open failure={}: {}",
                         this, ignored.getClass().getSimpleName(), e.getClass().getSimpleName(), ignored.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("handleOpenSuccess(" + this + ") inform listener open failure details", ignored);
                }
                if (log.isTraceEnabled()) {
                    Throwable[] suppressed = ignored.getSuppressed();
                    if (GenericUtils.length(suppressed) > 0) {
                        for (Throwable s : suppressed) {
                            log.trace("handleOpenSuccess(" + this + ") suppressed channel open failure signalling", s);
                        }
                    }
                }
            }

            this.openFuture.setException(e);
            this.closeFuture.setClosed();
            this.doCloseImmediately();
        } finally {
            notifyStateChanged(changeEvent);
        }
    }

    protected abstract void doOpen() throws IOException;

    @Override
    public void handleOpenFailure(Buffer buffer) {
        int reason = buffer.getInt();
        String msg = buffer.getString();
        String lang = buffer.getString();
        if (log.isDebugEnabled()) {
            log.debug("handleOpenFailure({}) reason={}, lang={}, msg={}",
                      this, SshConstants.getOpenErrorCodeName(reason), lang, msg);
        }

        this.openFailureReason = reason;
        this.openFailureMsg = msg;
        this.openFailureLang = lang;
        this.openFuture.setException(new SshException(msg));
        this.closeFuture.setClosed();
        this.doCloseImmediately();
        notifyStateChanged("SSH_MSG_CHANNEL_OPEN_FAILURE");
    }

    @Override
    protected void doWriteData(byte[] data, int off, int len) throws IOException {
        // If we're already closing, ignore incoming data
        if (isClosing()) {
            return;
        }
        if (asyncOut != null) {
            asyncOut.write(new ByteArrayBuffer(data, off, len));
        } else if (out != null) {
            out.write(data, off, len);
            out.flush();

            if (invertedOut == null) {
                Window wLocal = getLocalWindow();
                wLocal.consumeAndCheck(len);
            }
        } else {
            throw new IllegalStateException("No output stream for channel");
        }
    }

    @Override
    protected void doWriteExtendedData(byte[] data, int off, int len) throws IOException {
        // If we're already closing, ignore incoming data
        if (isClosing()) {
            return;
        }
        if (asyncErr != null) {
            asyncErr.write(new ByteArrayBuffer(data, off, len));
        } else if (err != null) {
            err.write(data, off, len);
            err.flush();

            if (invertedErr == null) {
                Window wLocal = getLocalWindow();
                wLocal.consumeAndCheck(len);
            }
        } else {
            throw new IllegalStateException("No error stream for channel");
        }
    }

    @Override
    public void handleWindowAdjust(Buffer buffer) throws IOException {
        super.handleWindowAdjust(buffer);
        if (asyncIn != null) {
            asyncIn.onWindowExpanded();
        }
    }

    @Override
    public Integer getExitStatus() {
        return exitStatusHolder.get();
    }

    @Override
    public String getExitSignal() {
        return exitSignalHolder.get();
    }
}
