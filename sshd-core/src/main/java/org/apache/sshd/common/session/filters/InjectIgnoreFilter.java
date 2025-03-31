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
import java.util.Objects;

import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.filter.InputHandler;
import org.apache.sshd.common.filter.IoFilter;
import org.apache.sshd.common.filter.OutputHandler;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.core.CoreModuleProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A filter that injects SSH_MSG_IGNORE messages depending on the configuration settings.
 * <p>
 * This filter should be placed below the KexFilter to ensure that it doesn't inject ignore message during KEX.
 * </p>
 */
public class InjectIgnoreFilter extends IoFilter {

    private static final Logger LOG = LoggerFactory.getLogger(InjectIgnoreFilter.class);

    private final PropertyResolver resolver;

    private final Random random;

    private final OutputHandler output = new Injector();

    public InjectIgnoreFilter(PropertyResolver resolver, Random random) {
        this.resolver = Objects.requireNonNull(resolver);
        this.random = Objects.requireNonNull(random);
    }

    @Override
    public InputHandler in() {
        return null;
    }

    @Override
    public OutputHandler out() {
        return output;
    }

    private class Injector implements OutputHandler {

        private Settings settings;

        private long ignoreCount;

        Injector() {
            super();
        }

        @Override
        public synchronized IoWriteFuture send(Buffer message) throws IOException {
            int cmd = message.rawByte(message.rpos()) & 0xFF;
            int length = shouldSendIgnore(cmd);
            if (length > 0) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Injector.send({}) injecting SSH_MSG_IGNORE", resolver);
                }
                owner().send(InjectIgnoreFilter.this, createIgnoreBuffer(length)).addListener(f -> {
                    Throwable t = f.getException();
                    if (t != null && (resolver instanceof Session)) {
                        ((Session) resolver).exceptionCaught(t);
                    }
                });
            }
            return owner().send(InjectIgnoreFilter.this, message);
        }

        private Settings getSettings() {
            if (settings == null) {
                int length = CoreModuleProperties.IGNORE_MESSAGE_SIZE.getRequired(resolver);
                long frequency = CoreModuleProperties.IGNORE_MESSAGE_FREQUENCY.getRequired(resolver);
                int variance = CoreModuleProperties.IGNORE_MESSAGE_VARIANCE.getRequired(resolver);
                if (variance >= frequency) {
                    variance = 0;
                }
                settings = new Settings(length, frequency, variance);
                if (!settings.isDisabled()) {
                    ignoreCount = calculateNextIgnorePacketCount(settings);
                }
            }
            return settings;
        }

        private long calculateNextIgnorePacketCount(Settings s) {
            if (s.variance == 0) {
                return s.frequency;
            }
            int extra = random.random(Math.abs(s.variance));
            long count = (s.variance < 0) ? (s.frequency - extra) : (s.frequency + extra);
            if (LOG.isTraceEnabled()) {
                LOG.trace("calculateNextIgnorePacketCount({}) count={}", resolver, count);
            }

            return count;
        }

        private int shouldSendIgnore(int cmd) {
            if (cmd <= SshConstants.SSH_MSG_KEX_LAST) {
                return 0;
            }
            Settings s = getSettings();
            if (s.isDisabled()) {
                return 0;
            }
            long count = --ignoreCount;
            if (count == 0) {
                ignoreCount = calculateNextIgnorePacketCount(s);
                return s.length;
            }
            return 0;
        }

        private Buffer createIgnoreBuffer(int length) {
            int size = length + random.random(length + 1);
            Buffer buffer = new ByteArrayBuffer(SshConstants.SSH_PACKET_HEADER_LEN + 1 + size + CryptFilter.MAX_PADDING + 64);
            buffer.rpos(SshConstants.SSH_PACKET_HEADER_LEN);
            buffer.wpos(SshConstants.SSH_PACKET_HEADER_LEN);
            buffer.putByte(SshConstants.SSH_MSG_IGNORE);
            int start = buffer.wpos();
            buffer.wpos(buffer.wpos() + size);
            random.fill(buffer.array(), start, size);
            return buffer;
        }
    }

    private static class Settings {
        final int length;
        final long frequency;
        final int variance;

        Settings(int length, long frequency, int variance) {
            this.length = length;
            this.frequency = frequency;
            this.variance = variance;
        }

        boolean isDisabled() {
            return length <= 0 || frequency <= 0 || variance < 0;
        }
    }
}
