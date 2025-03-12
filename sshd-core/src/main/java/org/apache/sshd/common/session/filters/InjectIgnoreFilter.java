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
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.filter.InputHandler;
import org.apache.sshd.common.filter.IoFilter;
import org.apache.sshd.common.filter.OutputHandler;
import org.apache.sshd.common.io.DefaultIoWriteFuture;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.core.CoreModuleProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A filter that injects ignore messages depending on the configuration settings.
 */
public class InjectIgnoreFilter extends IoFilter {

    private static final Logger LOG = LoggerFactory.getLogger(InjectIgnoreFilter.class);

    private static final long DISABLED = -1;

    private final PropertyResolver resolver;

    private final Random random;

    private final AtomicReference<Settings> settings = new AtomicReference<>();

    private final AtomicLong ignoreCount = new AtomicLong(DISABLED);

    public InjectIgnoreFilter(PropertyResolver resolver, Random random) {
        this.resolver = Objects.requireNonNull(resolver);
        this.random = Objects.requireNonNull(random);
    }

    private Settings getSettings() {
        Settings result = settings.get();
        if (result == null) {
            int length = CoreModuleProperties.IGNORE_MESSAGE_SIZE.getRequired(resolver);
            long frequency = CoreModuleProperties.IGNORE_MESSAGE_FREQUENCY.getRequired(resolver);
            int variance = CoreModuleProperties.IGNORE_MESSAGE_VARIANCE.getRequired(resolver);
            if (variance >= frequency) {
                variance = 0;
            }
            result = new Settings(length, frequency, variance);
            settings.set(result);
            ignoreCount.set(calculateNextIgnorePacketCount(result));
        }
        return result;
    }

    private long calculateNextIgnorePacketCount(Settings s) {
        if ((s.frequency <= 0) || (s.variance < 0)) {
            return DISABLED;
        }
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
        if (s.length <= 0) {
            return 0;
        }
        long count = ignoreCount.decrementAndGet();
        if (count < 0) {
            ignoreCount.set(DISABLED);
        } else if (count == 0) {
            ignoreCount.set(calculateNextIgnorePacketCount(s));
            return s.length;
        }
        return 0;
    }

    private Buffer createIgnoreBuffer(int length) {
        int size = length + random.random(length + 1);
        Buffer buffer = new ByteArrayBuffer(SshConstants.SSH_PACKET_HEADER_LEN + 1 + size + 255 + 64);
        buffer.rpos(SshConstants.SSH_PACKET_HEADER_LEN);
        buffer.wpos(SshConstants.SSH_PACKET_HEADER_LEN);
        buffer.putByte(SshConstants.SSH_MSG_IGNORE);
        int start = buffer.wpos();
        buffer.wpos(buffer.wpos() + size);
        random.fill(buffer.array(), start, size);
        return buffer;
    }

    @Override
    public InputHandler in() {
        return null;
    }

    @Override
    public OutputHandler out() {
        // TODO: problem here: If we do this via future chaining, then a subsequent call may actually overtake the
        // message, which may break KEX.
        // If we do lastWrite, we may get an unbounded chain of futures. Yuck.
        // If we place this filter above the KEX filter, it would be OK once we have the KEX filter with its queue in
        // place.
        return message -> {
            int cmd = message.rawByte(message.rpos()) & 0xFF;
            int length = shouldSendIgnore(cmd);
            if (length == 0) {
                return owner().send(InjectIgnoreFilter.this, message);
            }
            DefaultIoWriteFuture result = new DefaultIoWriteFuture(this, null);
            owner().send(this, createIgnoreBuffer(length)).addListener(baseSent -> {
                Throwable t = baseSent.getException();
                if (t != null) {
                    result.setValue(t);
                }
                try {
                    owner().send(InjectIgnoreFilter.this, message).addListener(sent -> {
                        result.setValue(sent.isWritten() ? Boolean.TRUE : sent.getException());
                    });
                } catch (IOException e) {
                    result.setValue(e);
                }
            });
            return result;
        };
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
    }
}
