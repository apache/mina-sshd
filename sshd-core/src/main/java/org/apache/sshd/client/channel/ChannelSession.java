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

import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.Buffer;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelSession extends AbstractClientChannel {

    private Thread streamPumper;

    public ChannelSession() {
        super("session");
    }

    public OpenFuture open() throws Exception {
        if (in == null || out == null || err == null) {
            throw new IllegalStateException("in, out and err streams should be set before opening channel");
        }
        return internalOpen();
    }

    @Override
    protected void doOpen() throws Exception {
        streamPumper = new Thread("ClientInputStreamPump") {
            @Override
            public void run() {
                pumpInputStream();
            }
        };
        // Interrupt does not really work and the thread will only exit when
        // the call to read() will return.  So ensure this thread is a daemon
        // to avoid blocking the whole app
        streamPumper.setDaemon(true);
        streamPumper.start();
    }

    @Override
    protected void doClose() {
        super.doClose();
        if (streamPumper != null) {
            streamPumper.interrupt();
            streamPumper = null;
        }
    }

    protected void pumpInputStream() {
        try {
            while (!closeFuture.isClosed()) {
                Buffer buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_DATA, 0);
                buffer.putInt(recipient);
                int wpos1 = buffer.wpos(); // keep buffer position to write data length later
                buffer.putInt(0);
                int wpos2 = buffer.wpos(); // keep buffer position for data write
                buffer.wpos(wpos2 + remoteWindow.getPacketSize()); // Make room
                int len = securedRead(in, buffer.array(), wpos2, remoteWindow.getPacketSize()); // read data into buffer
                if (len > 0) {
                    buffer.wpos(wpos1);
                    buffer.putInt(len);
                    buffer.wpos(wpos2 + len);
                    remoteWindow.waitAndConsume(len);
                    log.debug("Send SSH_MSG_CHANNEL_DATA on channel {}", id);
                    session.writePacket(buffer);
                } else {
                    sendEof();
                    break;
                }
            }
        } catch (Exception e) {
            if (!closing) {
                log.info("Caught exception", e);
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
            if (in != null && in.available() <= 0) {
                return n;
            }
        }
    }

}
