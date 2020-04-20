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

package org.apache.sshd.common.mac;

import java.nio.charset.StandardCharsets;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * @see    <A HREF="https://tools.ietf.org/html/rfc4231">RFC 4321</A>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class MacVectorsTest extends JUnitTestSupport {
    private final VectorSeed seed;
    private final Factory<? extends Mac> macFactory;
    private final byte[] expected;

    public MacVectorsTest(VectorSeed seed, String factoryName, String expected) {
        this.seed = Objects.requireNonNull(seed, "No seed");
        this.macFactory = ValidateUtils.checkNotNull(BuiltinMacs.fromFactoryName(factoryName), "Unknown MAC: %s", factoryName);
        this.expected = BufferUtils.decodeHex(BufferUtils.EMPTY_HEX_SEPARATOR, expected);
    }

    @Parameters(name = "factory={1}, expected={2}, seed={0}")
    @SuppressWarnings("checkstyle:MethodLength")
    public static Collection<Object[]> parameters() {
        List<Object[]> ret = new ArrayList<>();
        for (VectorTestData vector : Collections.unmodifiableList(
                Arrays.asList(
                        ///////////////// Test Cases for HMAC-MD5 ///////////////////////
                        // see https://tools.ietf.org/html/rfc2202
                        new VectorTestData(
                                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", false, "Hi There",
                                Arrays.asList(new SimpleImmutableEntry<>(
                                        BuiltinMacs.Constants.HMAC_MD5, // test case 1
                                        "9294727a3638bb1c13f48ef8158bfc9d"))),
                        new VectorTestData(
                                "Jefe", "what do ya want for nothing?",
                                Arrays.asList(new SimpleImmutableEntry<>(
                                        BuiltinMacs.Constants.HMAC_MD5, // test case 2
                                        "750c783e6ab0b503eaa86e310a5db738"))),
                        new VectorTestData(
                                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false, repeat("dd", 50), false,
                                Arrays.asList(new SimpleImmutableEntry<>(
                                        BuiltinMacs.Constants.HMAC_MD5, // test case 3
                                        "56be34521d144c88dbb8c733f0e8b3f6"))),
                        /*
                         * TODO see why it fails new
                         * VectorTestData("0102030405060708090a0b0c0d0e0f10111213141516171819", false, repeat("cd", 50),
                         * false, Arrays.asList(new SimpleImmutableEntry<>(BuiltinMacs.Constants.HMAC_MD5, // test case
                         * 4 "697eaf0aca3a3aea3a75164746ffaa79"))),
                         */
                        new VectorTestData(
                                "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", false, "Test With Truncation",
                                Arrays.asList(new SimpleImmutableEntry<>(
                                        BuiltinMacs.Constants.HMAC_MD5, // test case 5
                                        "56461ef2342edc00f9bab995690efd4c"),
                                        new SimpleImmutableEntry<>(
                                                BuiltinMacs.Constants.HMAC_MD5_96,
                                                "56461ef2342edc00f9bab995"))),
                        /*
                         * TODO see why it fails new VectorTestData(repeat("aa", 80), false,
                         * "Test Using Larger Than Block-Size Key - Hash Key First", Arrays.asList(new
                         * SimpleImmutableEntry<>(BuiltinMacs.Constants.HMAC_MD5, // test case 6
                         * "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"))),
                         */
                        /*
                         * TODO see why it fails new VectorTestData(repeat("aa", 80), false,
                         * "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
                         * Arrays.asList(new SimpleImmutableEntry<>(BuiltinMacs.Constants.HMAC_MD5, // test case 7
                         * "6f630fad67cda0ee1fb1f562db3aa53e"))),
                         */
                        ///////////////// Test Cases for HMAC-SHA-1 ///////////////////////
                        // see https://tools.ietf.org/html/rfc2202
                        new VectorTestData(
                                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", false, "Hi There",
                                Arrays.asList(new SimpleImmutableEntry<>(
                                        BuiltinMacs.Constants.HMAC_SHA1, // test case 1
                                        "b617318655057264e28bc0b6fb378c8ef146be00"))),
                        new VectorTestData(
                                "Jefe", "what do ya want for nothing?",
                                Arrays.asList(new SimpleImmutableEntry<>(
                                        BuiltinMacs.Constants.HMAC_SHA1, // test case 2
                                        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"))),
                        new VectorTestData(
                                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false, repeat("dd", 50), false,
                                Arrays.asList(new SimpleImmutableEntry<>(
                                        BuiltinMacs.Constants.HMAC_SHA1, // test case 3
                                        "125d7342b9ac11cd91a39af48aa17b4f63f175d3"))),
                        /*
                         * TODO see why it fails new
                         * VectorTestData("0102030405060708090a0b0c0d0e0f10111213141516171819", false, repeat("cd", 50),
                         * false, Arrays.asList(new SimpleImmutableEntry<>(BuiltinMacs.Constants.HMAC_SHA1, // test case
                         * 4 "4c9007f4026250c6bc8414f9bf50c86c2d7235da"))),
                         */
                        new VectorTestData(
                                "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", false, "Test With Truncation",
                                Arrays.asList(new SimpleImmutableEntry<>(
                                        BuiltinMacs.Constants.HMAC_SHA1, // test case 5
                                        "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"),
                                        new SimpleImmutableEntry<>(
                                                BuiltinMacs.Constants.HMAC_SHA1_96,
                                                "4c1a03424b55e07fe7f27be1"))),
                        /*
                         * TODO see why this fails new VectorTestData(repeat("aa", 80), false,
                         * "Test Using Larger Than Block-Size Key - Hash Key First", Arrays.asList(new
                         * SimpleImmutableEntry<>(BuiltinMacs.Constants.HMAC_SHA1, // test case 6
                         * "aa4ae5e15272d00e95705637ce8a3b55ed402112"))),
                         */

                        /*
                         * TODO see why it fails new VectorTestData(repeat("aa", 80), false,
                         * "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
                         * Arrays.asList(new SimpleImmutableEntry<>(BuiltinMacs.Constants.HMAC_SHA1, // test case 7
                         * "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"), new
                         * SimpleImmutableEntry<>(BuiltinMacs.Constants.HMAC_SHA1_96, "4c1a03424b55e07fe7f27be1"))),
                         */

                        /*
                         * TODO see why it fails new VectorTestData(repeat("aa", 80), false,
                         * "Test Using Larger Than Block-Size Key - Hash Key First", Arrays.asList(new
                         * SimpleImmutableEntry<>(BuiltinMacs.Constants.HMAC_SHA1, // test case 8
                         * "aa4ae5e15272d00e95705637ce8a3b55ed402112"))),
                         */

                        /*
                         * TODO see why it fails new VectorTestData(repeat("aa", 80), false,
                         * "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
                         * Arrays.asList(new SimpleImmutableEntry<>(BuiltinMacs.Constants.HMAC_SHA1, // test case 9
                         * "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"))),
                         */

                        ///////////////// Test Cases for HMAC-SHA-2 ///////////////////////
                        // see https://tools.ietf.org/html/rfc4231
                        new VectorTestData(
                                repeat("0b", 20), false, "Hi There",
                                // test case 1
                                Arrays.asList(
                                        new SimpleImmutableEntry<>(
                                                BuiltinMacs.Constants.HMAC_SHA2_256,
                                                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
                                        new SimpleImmutableEntry<>(
                                                BuiltinMacs.Constants.HMAC_SHA2_512,
                                                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"))),
                        new VectorTestData(
                                "Jefe", "what do ya want for nothing?",
                                // test case 2
                                Arrays.asList(
                                        new SimpleImmutableEntry<>(
                                                BuiltinMacs.Constants.HMAC_SHA2_256,
                                                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
                                        new SimpleImmutableEntry<>(
                                                BuiltinMacs.Constants.HMAC_SHA2_512,
                                                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"))),
                        new VectorTestData(
                                repeat("aa", 20), false, repeat("dd", 50), false,
                                // test case 3
                                Arrays.asList(
                                        new SimpleImmutableEntry<>(
                                                BuiltinMacs.Constants.HMAC_SHA2_256,
                                                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
                                        new SimpleImmutableEntry<>(
                                                BuiltinMacs.Constants.HMAC_SHA2_512,
                                                "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"))),
                        new VectorTestData(
                                "0102030405060708090a0b0c0d0e0f10111213141516171819", false, repeat("cd", 50), false,
                                // test case 4
                                Arrays.asList(
                                        new SimpleImmutableEntry<>(
                                                BuiltinMacs.Constants.HMAC_SHA2_256,
                                                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
                                        new SimpleImmutableEntry<>(
                                                BuiltinMacs.Constants.HMAC_SHA2_512,
                                                "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"))),

                        /*
                         * TODO see why it fails new VectorTestData(repeat("0c", 20), false, "Test With Truncation",
                         * Arrays.asList( // test case 5 new SimpleImmutableEntry<>(BuiltinMacs.Constants.HMAC_SHA2_256,
                         * "a3b6167473100ee06e0c796c2955552b"), new
                         * SimpleImmutableEntry<>(BuiltinMacs.Constants.HMAC_SHA2_512,
                         * "415fad6271580a531d4179bc891d87a6"))),
                         */

                        /*
                         * TODO see why it fails new VectorTestData(repeat("aa", 131), false,
                         * "Test Using Larger Than Block-Size Key - Hash Key First", Arrays.asList( // test case 6 new
                         * SimpleImmutableEntry<>(BuiltinMacs.Constants.HMAC_SHA2_256,
                         * "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"), new
                         * SimpleImmutableEntry<>(BuiltinMacs.Constants.HMAC_SHA2_512,
                         * "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
                         * ))),
                         */

                        /*
                         * TODO see why it fails new VectorTestData(repeat("aa", 131), false,
                         * "This is a test using a larger than block-size" + " key and a larger than block-size data." +
                         * " The key needs to be hashed before being used" + " by the HMAC algorithm", Arrays.asList( //
                         * test case 7 new SimpleImmutableEntry<>(BuiltinMacs.Constants.HMAC_SHA2_256,
                         * "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"), new
                         * SimpleImmutableEntry<>(BuiltinMacs.Constants.HMAC_SHA2_512,
                         * "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
                         * )))
                         */

                        // mark end
                        new VectorTestData("", false, "", false, Collections.emptyList())))) {
            for (Map.Entry<String, String> tc : vector.getResults()) {
                ret.add(new Object[] { vector, tc.getKey(), tc.getValue() });
            }
        }

        return ret;
    }

    @Test
    public void testStandardVectorMac() throws Exception {
        Mac mac = macFactory.create();
        mac.init(seed.getKey());
        mac.update(seed.getData());

        byte[] actual = new byte[mac.getBlockSize()];
        mac.doFinal(actual);
        assertArrayEquals("Mismatched results for actual=" + BufferUtils.toHex(BufferUtils.EMPTY_HEX_SEPARATOR, actual),
                expected, actual);
    }

    private static class VectorSeed {
        private final byte[] key;
        private final String keyString;
        private final byte[] data;
        private final String dataString;

        VectorSeed(String key, String data) {
            this.key = key.getBytes(StandardCharsets.UTF_8);
            this.keyString = key;
            this.data = data.getBytes(StandardCharsets.UTF_8);
            this.dataString = data;
        }

        VectorSeed(String key, boolean useKeyString, String data) {
            this.key = BufferUtils.decodeHex(BufferUtils.EMPTY_HEX_SEPARATOR, key);
            this.keyString = useKeyString ? new String(this.key, StandardCharsets.UTF_8) : key;
            this.data = data.getBytes(StandardCharsets.UTF_8);
            this.dataString = data;
        }

        VectorSeed(String key, boolean useKeyString, String data, boolean useDataString) {
            this.key = BufferUtils.decodeHex(BufferUtils.EMPTY_HEX_SEPARATOR, key);
            this.keyString = useKeyString ? new String(this.key, StandardCharsets.UTF_8) : key;
            this.data = BufferUtils.decodeHex(BufferUtils.EMPTY_HEX_SEPARATOR, data);
            this.dataString = useDataString ? new String(this.data, StandardCharsets.UTF_8) : data;
        }

        public byte[] getKey() {
            return key.clone(); // clone to avoid inadvertent change
        }

        public String getKeyString() {
            return keyString;
        }

        public byte[] getData() {
            return data.clone(); // clone to avoid inadvertent change
        }

        public String getDataString() {
            return dataString;
        }

        @Override
        public String toString() {
            return "key=" + trimToLength(getKeyString(), 32) + ", data=" + trimToLength(getDataString(), 32);
        }

        private static CharSequence trimToLength(CharSequence csq, int maxLen) {
            if (GenericUtils.length(csq) <= maxLen) {
                return csq;
            }

            return csq.subSequence(0, maxLen) + "...";
        }
    }

    private static class VectorTestData extends VectorSeed {
        private final Collection<Map.Entry<String, String>> results;

        VectorTestData(String key, String data, Collection<Map.Entry<String, String>> results) {
            super(key, data);
            this.results = results;
        }

        VectorTestData(String key, boolean useKeyString, String data, Collection<Map.Entry<String, String>> results) {
            super(key, useKeyString, data);
            this.results = results;
        }

        VectorTestData(String key, boolean useKeyString, String data, boolean useDataString,
                       Collection<Map.Entry<String, String>> results) {
            super(key, useKeyString, data, useDataString);
            this.results = results;
        }

        public Collection<Map.Entry<String, String>> getResults() {
            return results;
        }
    }
}
