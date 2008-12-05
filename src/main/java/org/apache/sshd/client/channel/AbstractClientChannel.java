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

import java.io.OutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.IoUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.AbstractChannel;
import org.apache.sshd.ClientChannel;
import org.apache.sshd.client.session.ClientSessionImpl;

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
    public void close() throws IOException {
        super.close();
        IoUtils.closeQuietly(in, out, err);
    }
    

    public int waitFor(int mask, long timeout) {
        long t = 0;
        synchronized (lock) {
            for (;;) {
                int cond = 0;
                if (closed) {
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

    protected void internalOpen() throws Exception {
        log.info("Send SSH_MSG_CHANNEL_OPEN on channel {}", id);
        Buffer buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN);
        buffer.putString(type);
        buffer.putInt(id);
        buffer.putInt(localWindow.getSize());
        buffer.putInt(localWindow.getPacketSize());
        session.writePacket(buffer);
        synchronized (lock) {
            while (!opened && !closed) {
                log.trace("Waiting for channel to be opened: opened={}, closed={}", Boolean.valueOf(opened), Boolean.valueOf(closed));
                lock.wait();
            }
        }
        log.info("Channel opened {}", id);
        if (closed) {
            throw new SshException("Unable to open channel: reason=" + openFailureReason + ", msg=" + openFailureMsg);
        }
    }

    public void internalOpenSuccess(int recipient, int rwsize, int rmpsize) {
        synchronized (lock) {
            this.recipient = recipient;
            this.remoteWindow.init(rwsize, rmpsize);
            this.opened = true;
            lock.notifyAll();
        }
    }

    public void internalOpenFailure(Buffer buffer) {
        int reason = buffer.getInt();
        String msg = buffer.getString();
        synchronized (lock) {
            this.openFailureReason = reason;
            this.openFailureMsg = msg;
            this.closed = true;
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
