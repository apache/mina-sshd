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
import java.util.concurrent.atomic.AtomicLong;

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

    private final AtomicLong adjustment = new AtomicLong();

    private long released;

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
     * @param resolver {@PropertyResolver} to access properties
     */
    public void init(PropertyResolver resolver) {
        init(CoreModuleProperties.WINDOW_SIZE.getRequired(resolver),
                CoreModuleProperties.MAX_PACKET_SIZE.getRequired(resolver),
                resolver);
        released = 0;
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

    /**
     * Updates the window once data that has arrived in a channel has been read, making available room for the sender
     * too send more data, sending a window adjust message if necessary.
     *
     * @param  len         length of data read from the channel
     * @throws IOException if sending a window adjust message fails
     */
    public void release(long len) throws IOException {
        checkInitialized("check");
        if (len < 0) {
            throw new IllegalArgumentException("LocalWindow: number of released bytes must be positive, was " + len);
        }
        long maxFree = getMaxSize();
        long packetSize = getPacketSize();
        boolean trySend = false;
        synchronized (lock) {
            released += len;
            // If the reader from the channel reads in small chunks (for instance, single bytes), we'll get called
            // frequently with very small "len". In such a case, the reader is likely to be (much) slower than the
            // sender, and we may end up sending a window adjustment for every single byte. Avoid that by requiring
            // at least some halfway reasonable amount having been released before sending a window adjustment.
            if (released > packetSize / 2 || released > maxFree / 10 || released > 16 * 1024) {
                // TODO make the adjust factor configurable via FactoryManager property
                long size = getSize();
                // Same logic as in OpenSSH
                if (size < maxFree / 2 || maxFree - size > 3 * packetSize) {
                    // Math.min() is just belt and suspenders; size + released <= maxFree should always be true
                    long newSize = Math.min(size + released, maxFree);
                    if (newSize > size) { // This, too, should always be true
                        long adjustSize = adjustment.addAndGet(newSize - size);
                        if (log.isDebugEnabled()) {
                            log.debug("Increase {}: released now {}, total {}, adjustment {}, new size {}", this, len, released,
                                    adjustSize, newSize);
                        }
                        released = 0;
                        trySend = true;
                        updateSize(newSize);
                    }
                }
            }
        }
        // If a window adjust message is to be sent do it outside of the lock.
        if (trySend) {
            long adjustSize = adjustment.getAndSet(0);
            if (adjustSize > 0) {
                getChannel().sendWindowAdjust(adjustSize);
            }
        }
    }

}
