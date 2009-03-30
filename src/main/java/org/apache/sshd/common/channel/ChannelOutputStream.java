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
package org.apache.sshd.common.channel;

import java.io.IOException;
import java.io.OutputStream;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.Buffer;
import org.slf4j.Logger;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public class ChannelOutputStream extends OutputStream {

    private final AbstractChannel channel;
    private final Window remoteWindow;
    private final Logger log;
    private final SshConstants.Message cmd;
    private final byte[] b = new byte[1];
    private Buffer buffer;
    private boolean closed;
    private int bufferLength;

    public ChannelOutputStream(AbstractChannel channel, Window remoteWindow, Logger log, SshConstants.Message cmd) {
        this.channel = channel;
        this.remoteWindow = remoteWindow;
        this.log = log;
        this.cmd = cmd;
        newBuffer();
    }

    public synchronized void write(int w) throws IOException {
        b[0] = (byte) w;
        write(b, 0, 1);
    }

    public synchronized void write(byte[] buf, int s, int l) throws IOException {
        if (closed) {
            throw new SshException("Already closed");
        }
        while (l > 0) {
            int _l = Math.min(l, remoteWindow.getPacketSize() - bufferLength);
            if (_l <= 0) {
                flush();
                continue;
            }
            buffer.putRawBytes(buf, s, _l);
            bufferLength += _l;
            s += _l;
            l -= _l;
        }
    }

    @Override
    public synchronized void flush() throws IOException {
        if (closed) {
            throw new SshException("Already closed");
        }
        int pos = buffer.wpos();
        if (bufferLength <= 0) {
            // No data to send
            return;
        }
        buffer.wpos(cmd == SshConstants.Message.SSH_MSG_CHANNEL_EXTENDED_DATA ? 14 : 10);
        buffer.putInt(bufferLength);
        buffer.wpos(pos);
        try {
            remoteWindow.waitAndConsume(bufferLength);
            log.debug("Send {} on channel {}", cmd, channel.getId());
            channel.getSession().writePacket(buffer);
        } catch (SshException e) {
            throw e;
        } catch (Exception e) {
            throw new SshException(e);
        } finally {
            newBuffer();
        }
    }

    @Override
    public synchronized void close() throws IOException {
        closed = true;
    }

    private void newBuffer() {
        buffer = channel.getSession().createBuffer(cmd);
        buffer.putInt(channel.getRecipient());
        if (cmd == SshConstants.Message.SSH_MSG_CHANNEL_EXTENDED_DATA) {
            buffer.putInt(1);
        }
        buffer.putInt(0);
        bufferLength = 0;
    }

}
