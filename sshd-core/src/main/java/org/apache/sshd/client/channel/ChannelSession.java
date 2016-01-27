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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.ChannelAsyncInputStream;
import org.apache.sshd.common.channel.ChannelAsyncOutputStream;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.channel.ChannelPipedInputStream;
import org.apache.sshd.common.channel.ChannelPipedOutputStream;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.threads.ThreadUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelSession extends AbstractClientChannel {

    private ExecutorService pumperService;
    private Future<?> pumper;
    private boolean shutdownPumper;

    public ChannelSession() {
        super("session");
    }

    @Override
    protected void doOpen() throws IOException {
        if (Streaming.Async.equals(streaming)) {
            asyncIn = new ChannelAsyncOutputStream(this, SshConstants.SSH_MSG_CHANNEL_DATA) {
                @SuppressWarnings("synthetic-access")
                @Override
                protected CloseFuture doCloseGracefully() {
                    try {
                        sendEof();
                    } catch (IOException e) {
                        Session session = getSession();
                        session.exceptionCaught(e);
                    }
                    return super.doCloseGracefully();
                }
            };
            asyncOut = new ChannelAsyncInputStream(this);
            asyncErr = new ChannelAsyncInputStream(this);
        } else {
            invertedIn = new ChannelOutputStream(this, getRemoteWindow(), log, SshConstants.SSH_MSG_CHANNEL_DATA, true);

            Window wLocal = getLocalWindow();
            if (out == null) {
                ChannelPipedInputStream pis = new ChannelPipedInputStream(this, wLocal);
                ChannelPipedOutputStream pos = new ChannelPipedOutputStream(pis);
                out = pos;
                invertedOut = pis;
            }
            if (err == null) {
                ChannelPipedInputStream pis = new ChannelPipedInputStream(this, wLocal);
                ChannelPipedOutputStream pos = new ChannelPipedOutputStream(pis);
                err = pos;
                invertedErr = pis;
            }

            if (in != null) {
                // allocate a temporary executor service if none provided
                ExecutorService service = getExecutorService();
                if (service == null) {
                    pumperService = ThreadUtils.newSingleThreadExecutor("ClientInputStreamPump[" + this.toString() + "]");
                } else {
                    pumperService = service;
                }

                // shutdown the temporary executor service if had to create it
                shutdownPumper = (pumperService != service) || isShutdownOnExit();

                // Interrupt does not really work and the thread will only exit when
                // the call to read() will return.  So ensure this thread is a daemon
                // to avoid blocking the whole app
                pumper = pumperService.submit(new Runnable() {
                    @Override
                    public void run() {
                        pumpInputStream();
                    }
                });
            }
        }
    }

    @Override
    protected RequestHandler.Result handleInternalRequest(String req, boolean wantReply, Buffer buffer) throws IOException {
        switch (req) {
            case "xon-xoff":
                return handleXonXoff(buffer, wantReply);
            default:
                return super.handleInternalRequest(req, wantReply, buffer);
        }
    }

    // see RFC4254 section 6.8
    protected RequestHandler.Result handleXonXoff(Buffer buffer, boolean wantReply) throws IOException {
        boolean clientCanDo = buffer.getBoolean();
        if (log.isDebugEnabled()) {
            log.debug("handleXonXoff({})[want-reply={}] client-can-do={}",
                      this, wantReply, clientCanDo);
        }

        return RequestHandler.Result.ReplySuccess;
    }

    @Override
    protected void doCloseImmediately() {
        if ((pumper != null) && (pumperService != null) && shutdownPumper && (!pumperService.isShutdown())) {
            try {
                if (!pumper.isDone()) {
                    pumper.cancel(true);
                }

                pumperService.shutdownNow();
            } catch (Exception e) {
                // we log it as DEBUG since it is relatively harmless
                if (log.isDebugEnabled()) {
                    log.debug("doCloseImmediately({}) failed {} to shutdown stream pumper: {}",
                              this, e.getClass().getSimpleName(), e.getMessage());
                }
                if (log.isTraceEnabled()) {
                    log.trace("doCloseImmediately(" + this + ") stream pumper shutdown error details", e);
                }
            } finally {
                pumper = null;
                pumperService = null;
            }
        }

        super.doCloseImmediately();
    }

    protected void pumpInputStream() {
        try {
            Session session = getSession();
            Window wRemote = getRemoteWindow();
            byte[] buffer = new byte[wRemote.getPacketSize()];
            while (!closeFuture.isClosed()) {
                int len = securedRead(in, buffer, 0, buffer.length);
                if (len < 0) {
                    if (log.isDebugEnabled()) {
                        log.debug("pumpInputStream({}) EOF signalled", this);
                    }
                    sendEof();
                    return;
                }

                session.resetIdleTimeout();
                if (len > 0) {
                    invertedIn.write(buffer, 0, len);
                    invertedIn.flush();
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("pumpInputStream({}) close future closed", this);
            }
        } catch (Exception e) {
            if (!isClosing()) {
                if (log.isDebugEnabled()) {
                    log.debug("pumpInputStream({}) Caught {} : {}", this, e.getClass().getSimpleName(), e.getMessage());
                }
                if (log.isTraceEnabled()) {
                    log.trace("pumpInputStream(" + this + ") caught exception details", e);
                }
                close(false);
            }
        }
    }

    //
    // On some platforms, a call to System.in.read(new byte[65536], 0,32768) always throws an IOException.
    // So we need to protect against that and chunk the call into smaller calls.
    // This problem was found on Windows, JDK 1.6.0_03-b05.
    //
    protected int securedRead(InputStream in, byte[] buf, int off, int len) throws IOException {
        int n = 0;
        for (;;) {
            int nread = in.read(buf, off + n, Math.min(1024, len - n));
            if (nread <= 0) {
                return (n == 0) ? nread : n;
            }
            n += nread;
            if (n >= len) {
                return n;
            }
            // if not closed but no bytes available, return
            if (in.available() <= 0) {
                return n;
            }
        }
    }
}
