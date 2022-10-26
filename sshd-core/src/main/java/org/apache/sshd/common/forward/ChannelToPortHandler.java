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

    public void sendToPort(byte cmd, byte[] data, int off, long len) throws IOException {
        ValidateUtils.checkTrue(len <= Integer.MAX_VALUE, "Data length exceeds int boundaries: %d", len);
        Buffer buf = ByteArrayBuffer.getCompactClone(data, off, (int) len);
        port.writeBuffer(buf).addListener(future -> {
            if (future.isWritten()) {
                handleWriteDataSuccess(cmd, buf.array(), 0, (int) len);
            } else {
                handleWriteDataFailure(cmd, buf.array(), 0, (int) len, future.getException());
            }
        });
    }

    protected void handleWriteDataSuccess(byte cmd, byte[] data, int off, int len) {
        checkWindow(cmd);
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
            checkWindow(cmd);
            channel.close(false);
        } else {
            // In case remote entity has closed the socket, data coming from the SSH channel should be
            // simply discarded
            if (log.isDebugEnabled()) {
                log.debug(
                        "handleWriteDataFailure({})[{}] ignoring writeDataFailure {} because ioSession {} is already closing ",
                        channel, SshConstants.getCommandMessageName(cmd & 0xFF), t, port);
            }
            checkWindow(cmd);
        }
    }

    private void checkWindow(byte cmd) {
        try {
            LocalWindow wLocal = channel.getLocalWindow();
            if (wLocal.isOpen()) {
                wLocal.check();
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
