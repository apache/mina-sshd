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

import java.util.HashMap;
import java.util.List;

import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.filter.DefaultFilterChain;
import org.apache.sshd.common.filter.FilterChain;
import org.apache.sshd.common.random.JceRandom;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.core.CoreModuleProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("NoIoTestCase")
class InjectIgnoreFilterTest extends FilterTestSupport {

    private static final Random RNG = new JceRandom();

    private PropertyResolver resolver;
    private OutgoingSink outputs;
    private InjectIgnoreFilter filterUnderTest;
    private IncomingSink inputs;

    private FilterChain filterChain;

    @BeforeEach
    void setupFilterChain() {
        outputs = new OutgoingSink();
        inputs = new IncomingSink();
        resolver = PropertyResolverUtils.toPropertyResolver(new HashMap<>());
        filterUnderTest = new InjectIgnoreFilter(resolver, RNG);

        filterChain = new DefaultFilterChain();
        filterChain.addLast(outputs);
        filterChain.addLast(filterUnderTest);
        filterChain.addLast(inputs);

        outputs.autoFulfill = true;
    }

    @Test
    void expectIgnores() throws Exception {
        final int frequency = Byte.SIZE;
        CoreModuleProperties.IGNORE_MESSAGE_SIZE.set(resolver, Short.SIZE);
        CoreModuleProperties.IGNORE_MESSAGE_FREQUENCY.set(resolver, (long) frequency);
        CoreModuleProperties.IGNORE_MESSAGE_VARIANCE.set(resolver, 0);

        Buffer msg = new ByteArrayBuffer(SshConstants.SSH_PACKET_HEADER_LEN + 1);
        msg.rpos(SshConstants.SSH_PACKET_HEADER_LEN);
        msg.wpos(SshConstants.SSH_PACKET_HEADER_LEN);
        msg.putByte((byte) 0xff);

        final int rounds = 10;
        for (int i = 0; i < frequency * rounds; i++) {
            filterChain.getLast().out().send(msg);
        }
        assertEquals((frequency + 1) * rounds, outputs.outputs.size());
        List<IoWriteFutureWithData> out = outputs.outputs;
        for (int i = 0; i < outputs.outputs.size();) {
            for (int j = 0; j < frequency - 1; j++) {
                Buffer data = out.get(i++).data;
                assertEquals(-1, data.rawByte(data.rpos()));
            }
            Buffer data = out.get(i++).data;
            assertEquals(SshConstants.SSH_MSG_IGNORE, data.rawByte(data.rpos()));
            data = out.get(i++).data;
            assertEquals(-1, data.rawByte(data.rpos()));
        }
    }
}
