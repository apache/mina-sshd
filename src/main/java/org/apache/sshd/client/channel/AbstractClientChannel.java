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
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.AbstractChannel;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.IoUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public abstract class AbstractClientChannel extends AbstractChannel implements ClientChannel {

    protected boolean opened;
    protected final String type;
    protected InputStream in;
    protected OutputStream out;
    protected OutputStream err;
    protected Integer exitStatus;
    protected String exitSignal;
    protected int openFailureReason;
    protected String openFailureMsg;
    protected OpenFuture openFuture;

    protected AbstractClientChannel(String type) {
        this.type = type;
    }

    public InputStream getIn() {
        return in;
    }

    public void setIn(InputStream in) {
        this.in = in;
    }

    public OutputStream getOut() {
        return out;
    }

    public void setOut(OutputStream out) {
        this.out = out;
    }

    public OutputStream getErr() {
        return err;
    }

    public void setErr(OutputStream err) {
        this.err = err;
    }

    public void init(ClientSessionImpl session, int id) {
        this.session = session;
        configureWindow();
        this.id = id;
    }

    @Override
    public CloseFuture close(final boolean immediately) {
        synchronized (lock) {
            if (opened) {
                super.close(immediately);
            } else if (openFuture != null) {
                if (immediately) {
                    openFuture.setException(new SshException("Channel closed"));
                    super.close(immediately);
                } else {
                    openFuture.addListener(new SshFutureListener<OpenFuture>() {
                        public void operationComplete(OpenFuture future) {
                            close(immediately);
                        }
                    });
                }
            } else {
                closeFuture.setClosed();
            }
        }
        return closeFuture;
    }

    @Override
    protected void doClose() {
        super.doClose();
        IoUtils.closeQuietly(in, out, err);
    }

    public int waitFor(int mask, long timeout) {
        long t = 0;
        synchronized (lock) {
            for (;;) {
                int cond = 0;
                if (closeFuture.isClosed()) {
                    cond |= CLOSED | EOF;
                }
                if (eof) {
                    cond |= EOF;
                }
                if (exitStatus != null) {
                    cond |= EXIT_STATUS;
                }
                if (exitSignal != null) {
                    cond |= EXIT_SIGNAL;
                }
                if ((cond & mask) != 0) {
                    log.trace("WaitFor call returning on channel {}, mask={}, cond={}", new Object[] { id, mask, cond });
                    return cond;
                }
                if (timeout > 0) {
                    if (t == 0) {
                        t = System.currentTimeMillis() + timeout;
                    } else {
                        timeout = t - System.currentTimeMillis();
                        if (timeout <= 0) {
                            cond |= TIMEOUT;
                            return cond;
                        }
                    }
                }
                try {
                    log.trace("Waiting for lock on channel {}, mask={}, cond={}", new Object[] { id, mask, cond });
                    if (timeout > 0) {
                        lock.wait(timeout);
                    } else {
                        lock.wait();
                    }
                    log.trace("Lock notified on channel {}", id);
                } catch (InterruptedException e) {
                    // Ignore
                }
            }
        }
    }

    protected OpenFuture internalOpen() throws Exception {
        if (closeFuture.isClosed()) {
            throw new SshException("Session has been closed");
        }
        openFuture = new DefaultOpenFuture(lock);
        log.info("Send SSH_MSG_CHANNEL_OPEN on channel {}", id);
        Buffer buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN);
        buffer.putString(type);
        buffer.putInt(id);
        buffer.putInt(localWindow.getSize());
        buffer.putInt(localWindow.getPacketSize());
        session.writePacket(buffer);
        return openFuture;
    }

    public void internalOpenSuccess(int recipient, int rwsize, int rmpsize) {
        synchronized (lock) {
            this.recipient = recipient;
            this.remoteWindow.init(rwsize, rmpsize);
            try {
                doOpenShell();
                this.opened = true;
                this.openFuture.setOpened();
            } catch (Exception e) {
                this.openFuture.setException(e);
                this.closeFuture.setClosed();
            } finally {
                lock.notifyAll();
            }
        }
    }

    protected abstract void doOpenShell() throws Exception;

    public void internalOpenFailure(Buffer buffer) {
        int reason = buffer.getInt();
        String msg = buffer.getString();
        synchronized (lock) {
            this.openFailureReason = reason;
            this.openFailureMsg = msg;
            this.openFuture.setException(new SshException(msg));
            this.closeFuture.setClosed();
            lock.notifyAll();
        }
    }

    protected void doWriteData(byte[] data, int off, int len) throws IOException {
        if (out != null) {
            out.write(data, off, len);
            out.flush();
        }
        localWindow.consumeAndCheck(len);
    }

    protected void doWriteExtendedData(byte[] data, int off, int len) throws IOException {
        if (err != null) {
            err.write(data, off, len);
            err.flush();
        }
        localWindow.consumeAndCheck(len);
    }

    public void handleRequest(Buffer buffer) throws IOException {
        log.info("Received SSH_MSG_CHANNEL_REQUEST on channel {}", id);
        String req = buffer.getString();
        if ("exit-status".equals(req)) {
            buffer.getBoolean();
            synchronized (lock) {
                exitStatus = Integer.valueOf(buffer.getInt());
                lock.notifyAll();
            }
        } else if ("exit-signal".equals(req)) {
            buffer.getBoolean();
            synchronized (lock) {
                exitSignal = buffer.getString();
                lock.notifyAll();
            }
        }
        // TODO: handle other channel requests
    }
}
