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
package org.apache.sshd.common.session.filters;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.filter.BufferInputHandler;
import org.apache.sshd.common.filter.InputHandler;
import org.apache.sshd.common.filter.IoFilter;
import org.apache.sshd.common.filter.OutputHandler;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A filter that decompresses incoming packets and compresses outgoing ones.
 */
public class CompressionFilter extends IoFilter {

    private static final Logger LOG = LoggerFactory.getLogger(CompressionFilter.class);

    private final AtomicReference<Compression> inbound = new AtomicReference<>();

    private final AtomicReference<Compression> outbound = new AtomicReference<>();

    private final Decompressor input = new Decompressor();

    private final Compressor output = new Compressor();

    private Session session;

    public CompressionFilter() {
        super();
    }

    public void setSession(Session session) {
        this.session = session;
    }

    public void setInputCompression(Compression compression) {
        inbound.set(compression);
    }

    public void setOutputCompression(Compression compression) {
        outbound.set(compression);
    }

    public Compression getInputCompression() {
        return inbound.get();
    }

    public Compression getOutputCompression() {
        return outbound.get();
    }

    public void enableInput() {
        this.input.delayedEnable.set(true);
    }

    public void enableOutput() {
        this.output.delayedEnable.set(true);
    }

    @Override
    public InputHandler in() {
        return input;
    }

    @Override
    public OutputHandler out() {
        return output;
    }

    public interface CompressionListener {

        void compressed();

    }

    private abstract class DelayedEnabled {

        AtomicBoolean delayedEnable = new AtomicBoolean();

        DelayedEnabled() {
            super();
        }

    }

    private class Decompressor extends DelayedEnabled implements BufferInputHandler {

        private Buffer buffer;

        Decompressor() {
            super();
        }

        @Override
        public void handleMessage(Buffer message) throws Exception {
            Compression comp = inbound.get();
            Buffer decompressed = message;
            if (comp != null && comp.isCompressionExecuted() && (delayedEnable.get() || !comp.isDelayed())) {
                decompressed = decompress(comp, message);
            }
            owner().passOn(CompressionFilter.this, decompressed);
        }

        private Buffer decompress(Compression comp, Buffer message) throws IOException {
            if (buffer == null) {
                buffer = new ByteArrayBuffer();
            } else {
                buffer.clear(true);
            }
            comp.uncompress(message, buffer);
            return buffer;
        }
    }

    private class Compressor extends DelayedEnabled implements OutputHandler {

        Compressor() {
            super();
        }

        @Override
        public synchronized IoWriteFuture send(Buffer message) throws IOException {
            if (message != null) {
                Compression comp = outbound.get();
                if (comp != null && comp.isCompressionExecuted() && (delayedEnable.get() || !comp.isDelayed())) {
                    int cmd = message.rawByte(message.rpos()) & 0xFF;
                    int oldLength = message.available();
                    comp.compress(message);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Compressor.send({}): compressed {} packet from {} to {} bytes", session,
                                SshConstants.getCommandMessageName(cmd), oldLength, message.available());
                    }
                }
            }
            return owner().send(CompressionFilter.this, message);
        }
    }

}
