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
package org.apache.sshd.client.x11;

import org.apache.sshd.client.channel.ChannelX11;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.util.io.IoUtils;
import org.slf4j.Logger;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class X11IoHandler implements IoHandler {
    private final ChannelX11 channel;
    private final Logger log;

    public X11IoHandler(ChannelX11 channel, Logger log) {
        this.channel = channel;
        this.log = log;
    }

    @Override
    public void sessionCreated(IoSession session) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("X11 session created");
        }
    }

    @Override
    public void sessionClosed(IoSession session) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("X11 session closed");
        }
        if (channel.isOpen() && !channel.isClosing() && !channel.isClosed()) {
            channel.close(true);
        }
    }

    @Override
    public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
        if (log.isErrorEnabled()) {
            log.error("X11 exception caught", cause);
        }
    }

    @Override
    public void messageReceived(IoSession session, org.apache.sshd.common.util.Readable message) throws Exception {
        final byte[] bytes = new byte[Math.min(IoUtils.DEFAULT_COPY_SIZE, message.available())];
        if (bytes.length < 1) {
            return;
        }

        while (message.available() > 0) {
            final int len = Math.min(message.available(), bytes.length);
            message.getRawBytes(bytes, 0, len);
            channel.getOut().write(bytes, 0, len);
        }

        channel.getOut().flush();
    }

}
