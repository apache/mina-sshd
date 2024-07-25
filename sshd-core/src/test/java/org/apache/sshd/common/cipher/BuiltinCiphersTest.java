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

package org.apache.sshd.common.cipher;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.Set;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.BuiltinCiphers.ParseResult;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class BuiltinCiphersTest extends BaseTestSupport {
    public BuiltinCiphersTest() {
        super();
    }

    @Test
    void blockSize() {
        for (BuiltinCiphers cipher : BuiltinCiphers.VALUES) {
            assertTrue(cipher.getCipherBlockSize() >= 8, "Cipher " + cipher + " block size too small");
        }
    }

    @Test
    void fromEnumName() {
        for (BuiltinCiphers expected : BuiltinCiphers.VALUES) {
            String name = expected.name();

            for (int index = 0; index < name.length(); index++) {
                BuiltinCiphers actual = BuiltinCiphers.fromString(name);
                assertSame(expected, actual, name + " - mismatched enum values");
                name = shuffleCase(name); // prepare for next time
            }
        }
    }

    @Test
    void fromFactoryName() {
        for (BuiltinCiphers expected : BuiltinCiphers.VALUES) {
            String name = expected.getName();

            for (int index = 0; index < name.length(); index++) {
                BuiltinCiphers actual = BuiltinCiphers.fromFactoryName(name);
                assertSame(expected, actual, name + " - mismatched enum values");
                name = shuffleCase(name); // prepare for next time
            }
        }
    }

    @Test
    void fromFactory() {
        for (BuiltinCiphers expected : BuiltinCiphers.VALUES) {
            if (!expected.isSupported()) {
                System.out.append("Skip unsupported cipher: ").println(expected);
                continue;
            }

            NamedFactory<Cipher> factory = expected;
            assertEquals(expected.getName(), factory.getName(), expected.name() + " - mismatched factory names");

            BuiltinCiphers actual = BuiltinCiphers.fromFactory(factory);
            assertSame(expected, actual, expected.getName() + " - mismatched enum values");
        }
    }

    @Test
    void allConstantsCovered() throws Exception {
        Set<BuiltinCiphers> avail = EnumSet.noneOf(BuiltinCiphers.class);
        Field[] fields = BuiltinCiphers.Constants.class.getFields();
        for (Field f : fields) {
            int mods = f.getModifiers();
            if (!Modifier.isStatic(mods)) {
                continue;
            }

            Class<?> type = f.getType();
            if (!String.class.isAssignableFrom(type)) {
                continue;
            }

            String name = Objects.toString(f.get(null), null);
            BuiltinCiphers value = BuiltinCiphers.fromFactoryName(name);
            assertNotNull(value, "No match found for " + name);
            assertTrue(avail.add(value), name + " re-specified");
        }

        assertEquals("Incomplete coverage", BuiltinCiphers.VALUES, avail);
    }

    // make sure that if a cipher is reported as supported we can indeed use it
    @Test
    void supportedCipher() throws Exception {
        Exception err = null;
        Random rnd = new Random(System.nanoTime());
        for (BuiltinCiphers c : BuiltinCiphers.VALUES) {
            if (c.isSupported()) {
                try {
                    testCipherEncryption(rnd, c.create());
                } catch (Exception e) {
                    System.err.println(
                            "Failed (" + e.getClass().getSimpleName() + ") to encrypt using " + c + ": " + e.getMessage());
                    err = e;
                }
            } else {
                System.out.append("Skip unsupported cipher: ").println(c);
            }
        }

        if (err != null) {
            throw err;
        }
    }

    // make sure that the reported support matches reality by trying to encrypt something
    @Test
    void cipherSupportDetection() throws Exception {
        Random rnd = new Random(System.nanoTime());
        for (BuiltinCiphers c : BuiltinCiphers.VALUES) {
            try {
                testCipherEncryption(rnd, c.create());
                assertTrue(c.isSupported(), "Mismatched support report for " + c);
            } catch (Exception e) {
                assertFalse(c.isSupported(), "Mismatched support report for " + c);
            }
        }
    }

    private static void testCipherEncryption(Random rnd, Cipher cipher) throws Exception {
        byte[] key = new byte[cipher.getKdfSize()];
        rnd.nextBytes(key);
        byte[] iv = new byte[cipher.getIVSize()];
        // ChaCha20 has an SSH packet sequence number as IV! Do not use random IVs with ChaCha20!
        if (cipher.getAlgorithm().startsWith("ChaCha20")) {
            iv[iv.length - 1] = 42;
        } else {
            rnd.nextBytes(iv);
        }
        cipher.init(Cipher.Mode.Encrypt, key, iv);

        byte[] data = new byte[cipher.getCipherBlockSize() + cipher.getAuthenticationTagSize()];
        for (int i = 0; i < cipher.getCipherBlockSize(); i += Integer.BYTES) {
            BufferUtils.putUInt(Integer.toUnsignedLong(rnd.nextInt()), data, i, Integer.BYTES);
        }

        cipher.update(data, 0, cipher.getCipherBlockSize());
    }

    @Test
    void parseCiphersList() {
        List<String> builtin = NamedResource.getNameList(BuiltinCiphers.VALUES);
        List<String> unknown = Arrays.asList(
                getClass().getPackage().getName(), getClass().getSimpleName(), getCurrentTestName());
        Random rnd = new Random();
        for (int index = 0; index < (builtin.size() + unknown.size()); index++) {
            Collections.shuffle(builtin, rnd);
            Collections.shuffle(unknown, rnd);

            List<String> weavedList = new ArrayList<>(builtin.size() + unknown.size());
            for (int bIndex = 0, uIndex = 0; (bIndex < builtin.size()) || (uIndex < unknown.size());) {
                boolean useBuiltin = false;
                if (bIndex < builtin.size()) {
                    useBuiltin = uIndex >= unknown.size() || rnd.nextBoolean();
                }

                if (useBuiltin) {
                    weavedList.add(builtin.get(bIndex));
                    bIndex++;
                } else if (uIndex < unknown.size()) {
                    weavedList.add(unknown.get(uIndex));
                    uIndex++;
                }
            }

            String fullList = GenericUtils.join(weavedList, ',');
            ParseResult result = BuiltinCiphers.parseCiphersList(fullList);
            List<String> parsed = NamedResource.getNameList(result.getParsedFactories());
            List<String> missing = result.getUnsupportedFactories();

            // makes sure not only that the contents are the same but also the order
            assertListEquals(fullList + "[parsed]", builtin, parsed);
            assertListEquals(fullList + "[unsupported]", unknown, missing);
        }
    }

    @Test
    void resolveFactoryOnBuiltinValues() {
        for (NamedFactory<Cipher> expected : BuiltinCiphers.VALUES) {
            String name = expected.getName();
            NamedFactory<Cipher> actual = BuiltinCiphers.resolveFactory(name);
            assertSame(expected, actual, name);
        }
    }

    @Test
    void notAllowedToRegisterBuiltinFactories() {
        for (CipherFactory expected : BuiltinCiphers.VALUES) {
            try {
                BuiltinCiphers.registerExtension(expected);
                fail("Unexpected success for " + expected.getName());
            } catch (IllegalArgumentException e) {
                // expected - ignored
            }
        }
    }

    @Test
    void notAllowedToOverrideRegisteredFactories() {
        assertThrows(IllegalArgumentException.class, () -> {
            CipherFactory expected = Mockito.mock(CipherFactory.class);
            Mockito.when(expected.getName()).thenReturn(getCurrentTestName());

            String name = expected.getName();
            try {
                for (int index = 1; index <= Byte.SIZE; index++) {
                    BuiltinCiphers.registerExtension(expected);
                    assertEquals(1, index, "Unexpected success at attempt #" + index);
                }
            } finally {
                BuiltinCiphers.unregisterExtension(name);
            }
        });
    }

    @Test
    void resolveFactoryOnRegisteredExtension() {
        CipherFactory expected = Mockito.mock(CipherFactory.class);
        Mockito.when(expected.getName()).thenReturn(getCurrentTestName());

        String name = expected.getName();
        try {
            assertNull(BuiltinCiphers.resolveFactory(name), "Extension already registered");
            BuiltinCiphers.registerExtension(expected);

            NamedFactory<Cipher> actual = BuiltinCiphers.resolveFactory(name);
            assertSame(expected, actual, "Mismatched resolved instance");
        } finally {
            NamedFactory<Cipher> actual = BuiltinCiphers.unregisterExtension(name);
            assertSame(expected, actual, "Mismatched unregistered instance");
            assertNull(BuiltinCiphers.resolveFactory(name), "Extension not un-registered");
        }
    }

}
