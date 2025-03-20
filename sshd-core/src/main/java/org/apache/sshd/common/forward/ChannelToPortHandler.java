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
package org.apache.sshd.common.forward;

import java.io.IOException;
import java.util.Objects;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.LocalWindow;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * Implements forwarding messages received from a channel to a port in TCP/IP port forwarding.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelToPortHandler extends AbstractLoggingBean {

    private final IoSession port;

    private final Channel channel;

    public ChannelToPortHandler(IoSession port, Channel channel) {
        this.port = Objects.requireNonNull(port, "No port IoSession");
        this.channel = Objects.requireNonNull(channel, "No Channel");
    }

    /**
     * Retrieves the {@link IoSession} for the port connection.
     *
     * @return the {@link IoSession}, never {@code null}
     */
    public IoSession getPortSession() {
        return port;
    }

    /**
     * Perform appropriate actions on the port session when the channel received an SSH_MSG_CHANNEL_EOF message.
     *
     * @throws IOException
     */
    public void handleEof() throws IOException {
        // Forward the EOF out to whatever is connected to the port by shutting down the output stream.
        port.shutdownOutputStream();
    }

    /**
     * Write data to the port directly without adjusting the channel window.
     *
     * @param  buffer      data to write to the port
     * @return             an {@link IoWriteFuture} fulfilled once the data has been written
     * @throws IOException if an error occurs
     */
    public IoWriteFuture sendToPort(Buffer buffer) throws IOException {
        return port.writeBuffer(buffer);
    }

    /**
     * Forwards data received on the SSH channel to the port and adjust the channel window once the data has been
     * written.
     *
     * @param  cmd         the SSH command, typically @link SshConstants#SSH_MSG_CHANNEL_DATA}, used for logging only
     * @param  data        to forward
     * @param  off         offset in {@code data} of the start of the data to forward
     * @param  len         number of bytes to forward
     * @throws IOException if an error occurs
     */
    public void sendToPort(byte cmd, byte[] data, int off, long len) throws IOException {
        ValidateUtils.checkTrue(len <= Integer.MAX_VALUE, "Data length exceeds int boundaries: %d", len);
        Buffer buf = ByteArrayBuffer.getCompactClone(data, off, (int) len);
        sendToPort(buf).addListener(future -> {
            if (future.isWritten()) {
                handleWriteDataSuccess(cmd, buf.array(), 0, (int) len);
            } else {
                handleWriteDataFailure(cmd, buf.array(), 0, (int) len, future.getException());
            }
        });
    }

    protected void handleWriteDataSuccess(byte cmd, byte[] data, int off, int len) {
        checkWindow(cmd, len);
    }

    protected void handleWriteDataFailure(byte cmd, byte[] data, int off, int len, Throwable t) {
        debug("handleWriteDataFailure({}, {})[{}] failed ({}) to write len={}: {}", channel, port,
                SshConstants.getCommandMessageName(cmd & 0xFF), t.getClass().getSimpleName(), len, t.getMessage(), t);

        if (port.isOpen()) {
            // SSHD-795 IOException (Broken pipe) on a socket local forwarding channel causes SSH client-server
            // connection down
            if (log.isDebugEnabled()) {
                log.debug("handleWriteDataFailure({})[{}] closing session={}", channel,
                        SshConstants.getCommandMessageName(cmd & 0xFF), port);
            }
            checkWindow(cmd, len);
            channel.close(false);
        } else {
            // In case remote entity has closed the socket, data coming from the SSH channel should be
            // simply discarded
            if (log.isDebugEnabled()) {
                log.debug(
                        "handleWriteDataFailure({})[{}] ignoring writeDataFailure {} because ioSession {} is already closing ",
                        channel, SshConstants.getCommandMessageName(cmd & 0xFF), t, port);
            }
            checkWindow(cmd, len);
        }
    }

    private void checkWindow(byte cmd, long len) {
        try {
            LocalWindow wLocal = channel.getLocalWindow();
            if (wLocal.isOpen()) {
                wLocal.release(len);
            }
        } catch (Throwable e) {
            if (log.isDebugEnabled()) {
                log.debug("handleWriteDataSuccess({})[{}] failed ({}) to check local window: {}", channel,
                        SshConstants.getCommandMessageName(cmd & 0xFF), e.getClass().getSimpleName(), e.getMessage());
            }
            channel.getSession().exceptionCaught(e);
        }
    }
}
