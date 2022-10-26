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
package org.apache.sshd.common.channel;

import java.io.IOException;
import java.io.StreamCorruptedException;

import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * A {@link Window} that describes how much data this side is prepared to receive from the peer. Initialized when the
 * channel is created. This side reduces the window by the amount of data received on reception; if it receives more
 * data than allowed, it closes the channel. Once the data received has been processed, for instance, passed on, this
 * side checks the current window size and if it is low, increases it and sends an SSH_MSG_CHANNEL_WINDOW_ADJUST message
 * to the peer, who then is allowed to send more data again.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LocalWindow extends Window {

    private final AbstractChannel channel;

    public LocalWindow(AbstractChannel channel, boolean isClient) {
        super(channel, isClient);
        this.channel = channel;
    }

    @Override // Co-variant override
    public AbstractChannel getChannel() {
        return channel;
    }

    /**
     * Initializes the {@link LocalWindow} with the packet and window sizes from the {@code resolver}.
     *
     * @param size       the initial window size
     * @param packetSize the peer's advertised maximum packet size
     * @param resolver   {@PropertyResolver} to access properties
     */
    public void init(PropertyResolver resolver) {
        init(CoreModuleProperties.WINDOW_SIZE.getRequired(resolver),
                CoreModuleProperties.MAX_PACKET_SIZE.getRequired(resolver),
                resolver);
    }

    @Override
    public void consume(long len) throws IOException {
        BufferUtils.validateUint32Value(len, "Invalid consumption length: %d");
        checkInitialized("consume");

        long remainLen;
        synchronized (lock) {
            remainLen = getSize() - len;
            if (remainLen >= 0L) {
                updateSize(remainLen);
            }
        }
        if (remainLen < 0L) {
            throw new StreamCorruptedException(
                    "consume(" + this + ") required length (" + len + ") above available: " + (remainLen + len));
        }
        if (log.isDebugEnabled()) {
            log.debug("Consume {} by {} down to {}", this, len, remainLen);
        }
    }

    public void check() throws IOException {
        checkInitialized("check");

        long maxFree = getMaxSize();
        long adjustSize = -1L;
        AbstractChannel channel = getChannel();
        synchronized (lock) {
            // TODO make the adjust factor configurable via FactoryManager property
            long size = getSize();
            if (size < (maxFree / 2)) {
                adjustSize = maxFree - size;
                channel.sendWindowAdjust(adjustSize);
                updateSize(maxFree);
            }
        }

        if (adjustSize >= 0L) {
            if (log.isDebugEnabled()) {
                log.debug("Increase {} by {} up to {}", this, adjustSize, maxFree);
            }
        }
    }

}
