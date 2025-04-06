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
import java.util.logging.Level;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.filter.BufferInputHandler;
import org.apache.sshd.common.filter.InputHandler;
import org.apache.sshd.common.filter.IoFilter;
import org.apache.sshd.common.filter.OutputHandler;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.logging.LoggingUtils;
import org.apache.sshd.common.util.logging.SimplifiedLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A simple packet logging filter. The filter produces trace logs of the message contents for debugging purposes; it
 * should be placed in the filter chain above the compression filter because otherwise it will log compressed or
 * encrypted message data, which is useless for debugging.
 */
public class PacketLoggingFilter extends IoFilter {

    private static final Logger LOG = LoggerFactory.getLogger(PacketLoggingFilter.class);

    private static final SimplifiedLog SIMPLE = LoggingUtils.wrap(LOG);

    private final InputHandler input;

    private final OutputHandler output;

    public PacketLoggingFilter(Session session, CryptFilter crypt) {
        Objects.requireNonNull(session);
        Objects.requireNonNull(crypt);
        this.input = new BufferInputHandler() {

            @Override
            public void handleMessage(Buffer message) throws Exception {
                int sequenceNumber = crypt.getInputSequenceNumber() - 1;
                if (LOG.isTraceEnabled()) {
                    message.dumpHex(SIMPLE, Level.FINEST,
                            "receivePacket(" + session + ") packet #" + sequenceNumber, session);
                }
                owner().passOn(message);
            }

        };
        this.output = new OutputHandler() {

            @Override
            public synchronized IoWriteFuture send(int cmd, Buffer message) throws IOException {
                if (message != null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("sendPacket({}) packet #{} command={}[{}] len={}", session, crypt.getOutputSequenceNumber(),
                                cmd, SshConstants.getCommandMessageName(cmd), message.available());
                    }
                    if (SIMPLE.isTraceEnabled()) {
                        message.dumpHex(SIMPLE, Level.FINEST,
                                "sendPacket(" + session + ") packet #" + crypt.getOutputSequenceNumber(), session);
                    }
                }
                return owner().send(cmd, message);
            }
        };
    }

    @Override
    public InputHandler in() {
        return input;
    }

    @Override
    public OutputHandler out() {
        return output;
    }
}
