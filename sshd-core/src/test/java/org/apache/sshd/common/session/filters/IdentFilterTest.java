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

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.filter.DefaultFilterChain;
import org.apache.sshd.common.filter.FilterChain;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.core.CoreModuleProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("NoIoTestCase")
class IdentFilterTest extends FilterTestSupport {

    private OutgoingSink outputs;
    private IdentFilter filterUnderTest;
    private IncomingSink inputs;

    private FilterChain filterChain;

    @BeforeEach
    void setupFilterChain() {
        outputs = new OutgoingSink();
        inputs = new IncomingSink();
        filterUnderTest = new IdentFilter();
        filterUnderTest.setIdentHandler(new SshIdentHandler() {

            @Override
            public boolean isServer() {
                return false;
            }

            @Override
            public List<String> readIdentification(Buffer buffer) {
                String text = str(buffer);
                int nl = text.indexOf('\n');
                if (nl < 0) {
                    return null;
                }
                buffer.rpos(buffer.rpos() + nl + 1);
                if (nl > 0 && text.charAt(nl - 1) == '\r') {
                    nl--;
                }
                return Collections.singletonList(text.substring(0, nl));
            }

            @Override
            public List<String> provideIdentification() {
                return Collections.singletonList("SSH-2.0-foo bar");
            }
        });
        filterChain = new DefaultFilterChain();
        filterChain.addLast(outputs);
        filterChain.addLast(filterUnderTest);
        filterChain.addLast(inputs);
    }

    @Test
    void normalOperation() throws Exception {
        IoWriteFuture future = filterChain.getLast().out().send(0, buf("kex-init"));
        assertFalse(future.isDone());
        assertEquals(1, outputs.outputs.size());
        IoWriteFutureWithData first = outputs.outputs.get(0);
        assertEquals("SSH-2.0-foo bar\r\n", str(first.data));
        first.setValue(Boolean.TRUE);
        assertFalse(future.isDone());
        assertEquals(2, outputs.outputs.size());
        IoWriteFutureWithData second = outputs.outputs.get(1);
        assertEquals("kex-init", str(second.data));
        second.setValue(Boolean.TRUE);
        assertTrue(future.isWritten());
    }

    @Test
    void secondWriteIsQueued() throws Exception {
        IoWriteFuture future = filterChain.getLast().out().send(0, buf("kex-init"));
        assertFalse(future.isDone());
        IoWriteFuture future2 = filterChain.getLast().out().send(0, buf("second"));
        assertEquals(1, outputs.outputs.size());
        IoWriteFutureWithData first = outputs.outputs.get(0);
        assertEquals("SSH-2.0-foo bar\r\n", str(first.data));
        outputs.autoFulfill = true;
        first.setValue(Boolean.TRUE);
        assertTrue(future.isWritten());
        assertTrue(future2.isWritten());
        assertEquals(3, outputs.outputs.size());
        IoWriteFutureWithData next = outputs.outputs.get(1);
        assertEquals("kex-init", str(next.data));
        assertTrue(next.isWritten());
        next = outputs.outputs.get(2);
        assertEquals("second", str(next.data));
        assertTrue(next.isWritten());
    }

    @Test
    void onlyIdent() throws Exception {
        IoWriteFuture future = filterChain.getLast().out().send(0, null);
        assertFalse(future.isDone());
        assertEquals(1, outputs.outputs.size());
        IoWriteFutureWithData first = outputs.outputs.get(0);
        assertEquals("SSH-2.0-foo bar\r\n", str(first.data));
        first.setValue(Boolean.TRUE);
        assertTrue(future.isWritten());
        assertEquals(1, outputs.outputs.size());
        outputs.autoFulfill = true;
        IoWriteFuture future2 = filterChain.getLast().out().send(0, buf("kex-init"));
        assertEquals(2, outputs.outputs.size());
        IoWriteFutureWithData second = outputs.outputs.get(1);
        assertEquals("kex-init", str(second.data));
        assertTrue(second.isWritten());
        assertTrue(future2.isWritten());
    }

    @Test
    void waitForPeer() throws Exception {
        filterUnderTest.setPropertyResolver(new PropertyResolver() {

            @Override
            public PropertyResolver getParentPropertyResolver() {
                return null;
            }

            @Override
            public Map<String, Object> getProperties() {
                Map<String, Object> map = new HashMap<>();
                map.put(CoreModuleProperties.SEND_IMMEDIATE_IDENTIFICATION.getName(), Boolean.FALSE);
                return map;
            }
        });
        outputs.autoFulfill = true;
        IoWriteFuture future = filterChain.getLast().out().send(0, buf("kex-init"));
        assertFalse(future.isDone());
        assertEquals(0, outputs.outputs.size());
        filterChain.getFirst().in().received(buf("SSH-2.0-"));
        assertFalse(future.isDone());
        assertEquals(0, outputs.outputs.size());
        assertEquals(0, inputs.buffers.size());
        filterChain.getFirst().in().received(buf("foo foo"));
        assertFalse(future.isDone());
        IoWriteFuture future2 = filterChain.getLast().out().send(0, buf("second"));
        assertFalse(future2.isDone());
        assertEquals(0, outputs.outputs.size());
        assertEquals(0, inputs.buffers.size());
        filterChain.getFirst().in().received(buf("bar\r\n second"));
        assertTrue(future.isWritten());
        assertTrue(future2.isWritten());
        assertEquals(3, outputs.outputs.size());
        IoWriteFutureWithData outFuture = outputs.outputs.get(0);
        assertTrue(outFuture.isWritten());
        assertEquals("SSH-2.0-foo bar\r\n", str(outFuture.data));
        outFuture = outputs.outputs.get(1);
        assertTrue(outFuture.isWritten());
        assertEquals("kex-init", str(outFuture.data));
        outFuture = outputs.outputs.get(2);
        assertTrue(outFuture.isWritten());
        assertEquals("second", str(outFuture.data));
        assertEquals(1, inputs.buffers.size());
        assertEquals(" second", str(inputs.buffers.get(0)));
        filterChain.getFirst().in().received(buf("third"));
        assertEquals(2, inputs.buffers.size());
        assertEquals(" second", str(inputs.buffers.get(0)));
        assertEquals("third", str(inputs.buffers.get(1)));
    }
}
