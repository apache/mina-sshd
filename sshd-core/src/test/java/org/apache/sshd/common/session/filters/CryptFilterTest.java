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

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.cipher.Cipher.Mode;
import org.apache.sshd.common.cipher.CipherFactory;
import org.apache.sshd.common.filter.DefaultFilterChain;
import org.apache.sshd.common.filter.FilterChain;
import org.apache.sshd.common.mac.BuiltinMacs;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.mac.MacFactory;
import org.apache.sshd.common.random.JceRandom;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.filters.CryptFilter.Counters;
import org.apache.sshd.common.session.filters.CryptFilter.Settings;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@Tag("NoIoTestCase")
class CryptFilterTest extends FilterTestSupport {

    private static final Random RNG = new JceRandom();

    private OutgoingSink outputs;
    private CryptFilter filterUnderTest;
    private IncomingSink inputs;

    private FilterChain filterChain;

    private Random random;

    @BeforeEach
    void setupFilterChain() {
        outputs = new OutgoingSink();
        inputs = new IncomingSink();
        filterUnderTest = new CryptFilter();

        filterChain = new DefaultFilterChain();
        filterChain.addLast(outputs);
        filterChain.addLast(filterUnderTest);
        filterChain.addLast(inputs);

        random = new Random() {

            private int i;

            @Override
            public String getName() {
                return "TestRandom";
            }

            @Override
            public int random(int n) {
                // Not random at all. Return increasing values so that we generate all possible padding lengths.
                return i++ % n;
            }

            @Override
            public void fill(byte[] bytes, int start, int len) {
                RNG.fill(bytes, start, len);
            }
        };
        filterUnderTest.setRandom(random);
    }

    private static CipherFactory getCipherFactory(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }
        CipherFactory result = BuiltinCiphers.resolveFactory(name);
        assertNotNull(result);
        assertTrue(result.isSupported());
        return result;
    }

    private static MacFactory getMacFactory(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }
        MacFactory result = BuiltinMacs.resolveFactory(name);
        assertNotNull(result);
        assertTrue(result.isSupported());
        return result;
    }

    private static Stream<Arguments> parameters() {
        return Stream.of( //
                Arguments.of(null, null), // No encryption, no MAC
                Arguments.of(BuiltinCiphers.cc20p1305_openssh.getName(), null), // AEAD
                Arguments.of(BuiltinCiphers.aes128cbc.getName(), BuiltinMacs.hmacsha256.getName()), //
                Arguments.of(BuiltinCiphers.aes128cbc.getName(), BuiltinMacs.hmacsha256etm.getName()), //
                Arguments.of(BuiltinCiphers.aes128ctr.getName(), BuiltinMacs.hmacsha256.getName()), //
                Arguments.of(BuiltinCiphers.aes128ctr.getName(), BuiltinMacs.hmacsha256etm.getName()), //
                Arguments.of(BuiltinCiphers.aes128gcm.getName(), null), // AEAD
                Arguments.of(BuiltinCiphers.aes128gcm.getName(), null), // AEAD
                // Some unsafe settings (cipher only, mac only)
                Arguments.of(BuiltinCiphers.aes128ctr.getName(), null), //
                Arguments.of(null, BuiltinMacs.hmacsha256.getName()), //
                Arguments.of(null, BuiltinMacs.hmacsha256etm.getName()), //
                Arguments.of(BuiltinCiphers.none.getName(), null), //
                Arguments.of(BuiltinCiphers.none.getName(), BuiltinMacs.hmacsha256.getName()), //
                Arguments.of(BuiltinCiphers.none.getName(), BuiltinMacs.hmacsha256etm.getName()) //
        );
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "cipher={0} mac={1}")
    void roundtrip(String cipherName, String macName) throws Exception {
        // INIT: Set up cipher and MAC

        CipherFactory cipherFactory = getCipherFactory(cipherName);
        Cipher inCipher = null;
        Cipher outCipher = null;
        if (cipherFactory != null) {
            byte[] key = new byte[cipherFactory.getKdfSize()];
            byte[] iv = new byte[cipherFactory.getIVSize()];
            inCipher = cipherFactory.create();
            outCipher = cipherFactory.create();
            RNG.fill(key);
            if (!inCipher.getAlgorithm().startsWith("ChaCha20")) {
                // ChaCha20 is initialized with the sequence number, not a random IV.
                RNG.fill(iv);
            }
            inCipher.init(Mode.Decrypt, key, iv);
            outCipher.init(Mode.Encrypt, key, iv);
        }
        MacFactory macFactory = getMacFactory(macName);
        Mac inMac = null;
        Mac outMac = null;
        if (macFactory != null) {
            byte[] key = new byte[macFactory.getBlockSize()];
            inMac = macFactory.create();
            outMac = macFactory.create();
            RNG.fill(key);
            inMac.init(key);
            outMac.init(key);
        }
        filterUnderTest.setInput(new Settings(inCipher, inMac), true);
        filterUnderTest.setOutput(new Settings(outCipher, outMac), true);

        // Now send 1000 random Buffers of different lengths through the filter.
        List<byte[]> originals = new ArrayList<>();
        long totalLength = 0;
        for (int i = 0; i < 1000; i++) {
            byte[] data = new byte[i + 1];
            RNG.fill(data);
            originals.add(data);
            totalLength += data.length + 5 + 4;
            Buffer b = new ByteArrayBuffer(data.length + 5 + 4);
            b.rpos(5);
            b.wpos(5);
            b.putBytes(data);
            filterChain.getLast().out().send(b);
        }
        assertEquals(1000, outputs.outputs.size());
        if (outCipher == null && outMac == null) {
            // No encryption: check that the buffers still match
            for (int i = 0; i < 1000; i++) {
                Buffer b = outputs.outputs.get(i).data;
                byte[] raw = b.array();
                assertEquals(0, b.rpos());
                byte[] original = originals.get(i);
                int length = BufferUtils.getInt(raw, 0, 4);
                assertTrue(length > 0);
                assertEquals(raw.length - 4, length);
                int padding = raw[4] & 0xFF;
                assertTrue(padding >= 4);
                assertEquals(original.length + 5 + 4, b.available() - padding);
                byte[] data = new byte[original.length];
                System.arraycopy(raw, 9, data, 0, data.length);
                assertArrayEquals(original, data, "Data mismatch at index " + i);
            }
        }
        // Collect them at the other end into one single big buffer.
        ByteArrayBuffer all = new ByteArrayBuffer();
        outputs.outputs.forEach(f -> all.putBuffer(f.data));
        all.compact();
        byte[] streamData = all.array();
        int streamLength = all.available();
        assertTrue(streamLength > totalLength);
        // Feed the data back, hacked into small pieces.
        int n = inputs.buffers.size();
        int nRead = 0;
        for (int i = 0; i < streamLength; i += 3) {
            Buffer b = new ByteArrayBuffer(streamData, i, Math.min(streamLength - i, 3));
            try {
                filterChain.getFirst().in().received(b);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Error after packet " + n + " at index " + i + ": " + e);
            }
            int nNew = inputs.buffers.size();
            if (nNew != n) {
                n = nNew;
                nRead++;
                b = inputs.buffers.get(n - 1);
                byte[] data = b.getBytes();
                assertEquals(0, b.available(), "Extra data at packet " + n + "after index " + i);
                assertArrayEquals(originals.get(n - 1), data, "Data mismatch at packet " + n + " after index " + i);
            }
        }
        // At the end, we should have received 1000 identical buffers.
        assertEquals(1000, nRead);
        Counters inCounts = filterUnderTest.getInputCounters();
        Counters outCounts = filterUnderTest.getOutputCounters();
        assertTrue(inCounts.getBlocks() > 0);
        assertTrue(inCounts.getBytes() > 0);
        assertTrue(inCounts.getPackets() > 0);
        assertEquals(inCounts.getBlocks(), outCounts.getBlocks());
        assertEquals(inCounts.getBytes(), outCounts.getBytes());
        assertEquals(inCounts.getPackets(), outCounts.getPackets());
    }
}
