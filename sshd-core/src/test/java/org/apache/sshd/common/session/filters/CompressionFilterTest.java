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

import java.util.stream.Stream;

import org.apache.sshd.common.compression.BuiltinCompressions;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.compression.Compression.Type;
import org.apache.sshd.common.compression.CompressionFactory;
import org.apache.sshd.common.filter.DefaultFilterChain;
import org.apache.sshd.common.filter.FilterChain;
import org.apache.sshd.common.random.JceRandom;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@Tag("NoIoTestCase")
class CompressionFilterTest extends FilterTestSupport {

    private static final Random RNG = new JceRandom();

    private OutgoingSink outputs;
    private CryptFilter crypt;
    private CompressionFilter filterUnderTest;
    private IncomingSink inputs;

    private FilterChain filterChain;

    @BeforeEach
    void setupFilterChain() {
        outputs = new OutgoingSink();
        inputs = new IncomingSink();
        // Include a crypt filter so that we can be sure that we compress only the data, not the SSH packet header stuff
        // or padding. We don't encrypt, though.
        crypt = new CryptFilter();
        filterUnderTest = new CompressionFilter();

        filterChain = new DefaultFilterChain();
        filterChain.addLast(outputs);
        filterChain.addLast(crypt);
        filterChain.addLast(filterUnderTest);
        filterChain.addLast(inputs);
    }

    private static Stream<Arguments> parameters() {
        return Stream.of( // Compression, isAuthenticated
                Arguments.of(null, false), //
                Arguments.of(null, true), //
                Arguments.of(BuiltinCompressions.none.getName(), false), //
                Arguments.of(BuiltinCompressions.none.getName(), true), //
                Arguments.of(BuiltinCompressions.zlib.getName(), false), //
                Arguments.of(BuiltinCompressions.zlib.getName(), true), //
                Arguments.of(BuiltinCompressions.delayedZlib.getName(), false), //
                Arguments.of(BuiltinCompressions.delayedZlib.getName(), true) //
        );
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "compression={0} auth={1}")
    void roundtrip(String compression, boolean isAuthenticated) throws Exception {
        Compression inCompression = null;
        Compression outCompression = null;
        if (!GenericUtils.isEmpty(compression)) {
            CompressionFactory factory = BuiltinCompressions.resolveFactory(compression);
            assertNotNull(factory);
            assertTrue(factory.isSupported());
            inCompression = factory.create();
            outCompression = factory.create();
            inCompression.init(Type.Inflater, 9);
            outCompression.init(Type.Deflater, 9);
        }
        boolean expectSame = outCompression == null || !outCompression.isCompressionExecuted()
                || outCompression.isDelayed() && !isAuthenticated;
        filterUnderTest.setInputCompression(inCompression);
        filterUnderTest.setOutputCompression(outCompression);

        if (isAuthenticated) {
            filterUnderTest.enableInput();
            filterUnderTest.enableOutput();
        }

        // Send 1000 random Buffers of different lengths through the filter.
        // Reflect them back, and compare the result.
        for (int i = 0; i < 1000; i++) {
            byte[] original = new byte[i + 4000];
            RNG.fill(original);
            Buffer b = new ByteArrayBuffer(original.length + 5 + 4);
            b.rpos(5);
            b.wpos(5);
            b.putBytes(original);
            filterChain.getLast().out().send(0, b);
            assertEquals(1, outputs.outputs.size());
            IoWriteFutureWithData outFuture = outputs.outputs.get(0);
            outputs.outputs.clear();
            outFuture.setValue(Boolean.TRUE); // Not really needed here since we don't care
            // Check the raw data
            if (expectSame) {
                byte[] raw = new byte[original.length];
                byte[] packet = outFuture.data.array();
                System.arraycopy(packet, outFuture.data.rpos() + 5 + 4, raw, 0, raw.length);
                assertArrayEquals(original, raw);
            } else {
                // Expect a difference in the first few payload bytes
                byte[] packet = outFuture.data.array();
                boolean different = false;
                for (int j = 0; !different && j < 10; j++) {
                    different = original[j] != packet[outFuture.data.rpos() + 5 + j];
                }
                assertTrue(different, "Data was unexpectely the same at iteration " + i);
            }
            filterChain.getFirst().in().received(outFuture.data);
            assertEquals(1, inputs.buffers.size());
            Buffer received = inputs.buffers.get(0);
            inputs.buffers.clear();
            byte[] data = received.getBytes();
            assertEquals(0, received.available());
            assertArrayEquals(original, data);
        }
    }
}
