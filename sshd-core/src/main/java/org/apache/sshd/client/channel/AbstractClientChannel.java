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
package org.apache.sshd.client.channel;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.sshd.ClientChannel;
import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.RequestHandler;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.AbstractChannel;
import org.apache.sshd.common.channel.ChannelAsyncInputStream;
import org.apache.sshd.common.channel.ChannelAsyncOutputStream;
import org.apache.sshd.common.io.IoInputStream;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.IoUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractClientChannel extends AbstractChannel implements ClientChannel {

    protected volatile boolean opened;
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
    protected Integer exitStatus;
    protected String exitSignal;
    protected int openFailureReason;
    protected String openFailureMsg;
    protected OpenFuture openFuture;

    protected AbstractClientChannel(String type) {
        this.type = type;
        this.streaming = Streaming.Sync;
        addRequestHandler(new ExitStatusChannelRequestHandler());
        addRequestHandler(new ExitSignalChannelRequestHandler());
    }

    public Streaming getStreaming() {
        return streaming;
    }

    public void setStreaming(Streaming streaming) {
        this.streaming = streaming;
    }

    public IoOutputStream getAsyncIn() {
        return asyncIn;
    }

    public IoInputStream getAsyncOut() {
        return asyncOut;
    }

    public IoInputStream getAsyncErr() {
        return asyncErr;
    }

    public OutputStream getInvertedIn() {
        return invertedIn;
    }

    public InputStream getIn() {
        return in;
    }

    public void setIn(InputStream in) {
        this.in = in;
    }

    public InputStream getInvertedOut() {
        return invertedOut;
    }

    public OutputStream getOut() {
        return out;
    }

    public void setOut(OutputStream out) {
        this.out = out;
    }

    public InputStream getInvertedErr() {
        return invertedErr;
    }

    @Deprecated
    public OutputStream getErr() {
        return err;
    }

    public void setErr(OutputStream err) {
        this.err = err;
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder()
                .when(openFuture)
                .run(new Runnable() {
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

    public int waitFor(int mask, long timeout) {
        long t = 0;
        synchronized (lock) {
            for (;;) {
                int cond = 0;
                if (openFuture != null && openFuture.isOpened()) {
                    cond |= ClientChannel.OPENED;
                }
                if (closeFuture.isClosed()) {
                    cond |= ClientChannel.CLOSED | ClientChannel.EOF;
                }
                if (eof) {
                    cond |= ClientChannel.EOF;
                }
                if (exitStatus != null) {
                    cond |= ClientChannel.EXIT_STATUS;
                }
                if (exitSignal != null) {
                    cond |= ClientChannel.EXIT_SIGNAL;
                }
                if ((cond & mask) != 0) {
                    log.trace("WaitFor call returning on channel {}, mask={}, cond={}", new Object[] { this, mask, cond });
                    return cond;
                }
                if (timeout > 0) {
                    if (t == 0) {
                        t = System.currentTimeMillis() + timeout;
                    } else {
                        timeout = t - System.currentTimeMillis();
                        if (timeout <= 0) {
                            cond |= ClientChannel.TIMEOUT;
                            return cond;
                        }
                    }
                }
                try {
                    log.trace("Waiting for lock on channel {}, mask={}, cond={}", new Object[] { this, mask, cond });
                    if (timeout > 0) {
                        lock.wait(timeout);
                    } else {
                        lock.wait();
                    }
                    log.trace("Lock notified on channel {}", this);
                } catch (InterruptedException e) {
                    // Ignore
                }
            }
        }
    }

    public synchronized OpenFuture open() throws IOException {
        if (isClosing()) {
            throw new SshException("Session has been closed");
        }
        openFuture = new DefaultOpenFuture(lock);
        log.debug("Send SSH_MSG_CHANNEL_OPEN on channel {}", this);
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_OPEN);
        buffer.putString(type);
        buffer.putInt(id);
        buffer.putInt(localWindow.getSize());
        buffer.putInt(localWindow.getPacketSize());
        writePacket(buffer);
        return openFuture;
    }

    public OpenFuture open(int recipient, int rwsize, int rmpsize, Buffer buffer) {
        throw new IllegalStateException();
    }

    public void handleOpenSuccess(int recipient, int rwsize, int rmpsize, Buffer buffer) {
        this.recipient = recipient;
        this.remoteWindow.init(rwsize, rmpsize);
        try {
            doOpen();
            this.opened = true;
            this.openFuture.setOpened();
        } catch (Exception e) {
            this.openFuture.setException(e);
            this.closeFuture.setClosed();
            this.doCloseImmediately();
        } finally {
            notifyStateChanged();
        }
    }

    protected abstract void doOpen() throws IOException;

    public void handleOpenFailure(Buffer buffer) {
        int reason = buffer.getInt();
        String msg = buffer.getString();
        this.openFailureReason = reason;
        this.openFailureMsg = msg;
        this.openFuture.setException(new SshException(msg));
        this.closeFuture.setClosed();
        this.doCloseImmediately();
        notifyStateChanged();
    }

    protected void doWriteData(byte[] data, int off, int len) throws IOException {
        // If we're already closing, ignore incoming data
        if (isClosing()) {
            return;
        }
        if (asyncOut != null) {
            asyncOut.write(new Buffer(data, off, len));
        } else if (out != null) {
            out.write(data, off, len);
            out.flush();
            if (invertedOut == null) {
                localWindow.consumeAndCheck(len);
            }
        } else {
            throw new IllegalStateException("No output stream for channel");
        }
    }

    protected void doWriteExtendedData(byte[] data, int off, int len) throws IOException {
        // If we're already closing, ignore incoming data
        if (isClosing()) {
            return;
        }
        if (asyncErr != null) {
            asyncErr.write(new Buffer(data, off, len));
        } else if (err != null) {
            err.write(data, off, len);
            err.flush();
            if (invertedErr == null) {
                localWindow.consumeAndCheck(len);
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

    public Integer getExitStatus() {
        return exitStatus;
    }

    private class ExitStatusChannelRequestHandler implements RequestHandler<Channel> {
        public Result process(Channel channel, String request, boolean wantReply, Buffer buffer) throws Exception {
            if (request.equals("exit-status")) {
                exitStatus = buffer.getInt();
                notifyStateChanged();
                return Result.ReplySuccess;
            }
            return Result.Unsupported;
        }
    }

    private class ExitSignalChannelRequestHandler implements RequestHandler<Channel> {
        public Result process(Channel channel, String request, boolean wantReply, Buffer buffer) throws Exception {
            if (request.equals("exit-signal")) {
                exitSignal = buffer.getString();
                notifyStateChanged();
                return Result.ReplySuccess;
            }
            return Result.Unsupported;
        }
    }

}
