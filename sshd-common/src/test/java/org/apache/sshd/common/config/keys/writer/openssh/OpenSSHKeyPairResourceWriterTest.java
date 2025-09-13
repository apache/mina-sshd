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

package org.apache.sshd.common.config.keys.writer.openssh;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.io.output.SecureByteArrayOutputStream;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
class OpenSSHKeyPairResourceWriterTest extends JUnitTestSupport {

    static Collection<TestData> parameters() {
        List<TestData> result = new ArrayList<>();
        result.add(new TestData("RSA", 1024));
        result.add(new TestData("RSA", 2048));
        result.add(new TestData("DSA", 1024));
        result.add(new TestData("ECDSA", 256));
        result.add(new TestData("ECDSA", 384));
        result.add(new TestData("ECDSA", 521));
        if (SecurityUtils.isEDDSACurveSupported()) {
            result.add(new TestData(SecurityUtils.ED25519, -1));
        }

        return result;
    }

    private KeyPair generateKey(TestData data) throws Exception {
        KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator(data.algorithm);
        if (data.keySize > 0) {
            generator.initialize(data.keySize);
        }
        return generator.generateKeyPair();
    }

    private boolean compare(KeyPair a, KeyPair b) {
        // Compares both public and private keys.
        return KeyUtils.compareKeyPairs(a, b);
    }

    private static void writeToFile(Path file, byte[] sensitiveData)
            throws IOException {
        try (ByteChannel out = Files.newByteChannel(file,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            ByteBuffer buf = ByteBuffer.wrap(sensitiveData);
            while (buf.hasRemaining()) {
                out.write(buf);
            }
        } finally {
            Arrays.fill(sensitiveData, (byte) 0);
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void fileRoundtripNoEncryption(TestData data) throws Exception {
        final KeyPair testKey = generateKey(data);
        Path tmp = getTemporaryOutputFile();
        try (SecureByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(testKey, "a comment", null, out);
            writeToFile(tmp, out.toByteArray());
        }
        try (InputStream in = Files.newInputStream(tmp)) {
            KeyPair key = SecurityUtils.loadKeyPairIdentities(null,
                    new PathResource(tmp), in, null).iterator().next();
            assertNotNull(key, "No key pair parsed");
            assertKeyPairEquals("Mismatched recovered keys", testKey, key);
            assertTrue(compare(key, testKey), "Keys should be equal");
            Path tmp2 = getTemporaryOutputFile("again");
            try (SecureByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
                OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(key, "a comment", null, out);
                writeToFile(tmp2, out.toByteArray());
            }
            try (InputStream in2 = Files.newInputStream(tmp2)) {
                KeyPair key2 = SecurityUtils.loadKeyPairIdentities(null,
                        new PathResource(tmp2), in2, null).iterator().next();
                assertNotNull(key2, "No key pair parsed");
                assertKeyPairEquals("Mismatched recovered keys", testKey, key2);
                assertTrue(compare(key2, testKey), "Keys should be equal");

                assertKeyPairEquals("Mismatched recovered keys", key, key2);
                assertTrue(compare(key2, key), "Keys should be equal");
            }
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void fileRoundtripWithEncryption(TestData data) throws Exception {
        final KeyPair testKey = generateKey(data);
        Path tmp = getTemporaryOutputFile();
        OpenSSHKeyEncryptionContext options = new OpenSSHKeyEncryptionContext();
        options.setPassword("nonsense");
        options.setCipherName("AES");
        options.setCipherMode("CTR");
        options.setCipherType("256");

        try (ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(testKey, "a comment", options, out);
            writeToFile(tmp, out.toByteArray());
        }

        try (InputStream in = Files.newInputStream(tmp)) {
            KeyPair key = SecurityUtils.loadKeyPairIdentities(null,
                    new PathResource(tmp), in, FilePasswordProvider.of("nonsense")).iterator().next();
            assertNotNull(key, "No key pair parsed");
            assertKeyPairEquals("Mismatched recovered keys", testKey, key);
            assertTrue(compare(key, testKey), "Keys should be equal");
            Path tmp2 = getTemporaryOutputFile("again");
            try (ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
                OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(key, "a comment", options, out);
                writeToFile(tmp2, out.toByteArray());
            }
            try (InputStream in2 = Files.newInputStream(tmp2)) {
                KeyPair key2 = SecurityUtils.loadKeyPairIdentities(null,
                        new PathResource(tmp2), in2, FilePasswordProvider.of("nonsense")).iterator().next();
                assertNotNull(key2, "No key pair parsed");
                assertKeyPairEquals("Mismatched recovered keys", testKey, key2);
                assertTrue(compare(key2, testKey), "Keys should be equal");

                assertKeyPairEquals("Mismatched recovered keys", key, key2);
                assertTrue(compare(key2, key), "Keys should be equal");
            }
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void fileRoundtripAsymmetric(TestData data) throws Exception {
        final KeyPair testKey = generateKey(data);
        // Write first unencrypted, then encrypted. read both and compare.
        Path tmp = getTemporaryOutputFile();
        try (ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(testKey, "a comment", null, out);
            writeToFile(tmp, out.toByteArray());
        }
        try (InputStream in = Files.newInputStream(tmp)) {
            KeyPair key = SecurityUtils.loadKeyPairIdentities(null,
                    new PathResource(tmp), in, null).iterator().next();
            assertNotNull(key, "No key pair parsed");
            assertKeyPairEquals("Mismatched recovered keys", testKey, key);
            assertTrue(compare(key, testKey), "Keys should be equal");
            Path tmp2 = getTemporaryOutputFile("again");
            try (ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
                OpenSSHKeyEncryptionContext options = new OpenSSHKeyEncryptionContext();
                options.setPassword("nonsense");
                options.setCipherName("AES");
                options.setCipherMode("CTR");
                options.setCipherType("256");
                OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(key, "a comment", options, out);
                writeToFile(tmp2, out.toByteArray());
            }
            try (InputStream in2 = Files.newInputStream(tmp2)) {
                KeyPair key2 = SecurityUtils.loadKeyPairIdentities(null,
                        new PathResource(tmp2), in2, FilePasswordProvider.of("nonsense")).iterator().next();
                assertNotNull(key2, "No key pair parsed");
                assertKeyPairEquals("Mismatched recovered keys", testKey, key2);
                assertTrue(compare(key2, testKey), "Keys should be equal");

                assertKeyPairEquals("Mismatched recovered keys", key, key2);
                assertTrue(compare(key2, key), "Keys should be equal");
            }
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void writePrivateKeyNoEncryption(TestData data) throws Exception {
        final KeyPair testKey = generateKey(data);
        Path tmp = getTemporaryOutputFile();
        try (ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(testKey, "a comment", null, out);
            writeToFile(tmp, out.toByteArray());
        }
        try (InputStream in = Files.newInputStream(tmp)) {
            KeyPair key = SecurityUtils.loadKeyPairIdentities(null,
                    new PathResource(tmp), in, null).iterator().next();
            assertNotNull(key, "No key pair parsed");
            assertKeyPairEquals("Mismatched recovered keys", testKey, key);
            assertTrue(compare(key, testKey), "Keys should be equal");
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void writePrivateKeyNoPassword(TestData data) throws Exception {
        final KeyPair testKey = generateKey(data);
        Path tmp = getTemporaryOutputFile();
        try (ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            OpenSSHKeyEncryptionContext options = new OpenSSHKeyEncryptionContext();
            OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(testKey, "a comment", options, out);
            writeToFile(tmp, out.toByteArray());
        }
        try (InputStream in = Files.newInputStream(tmp)) {
            KeyPair key = SecurityUtils.loadKeyPairIdentities(null,
                    new PathResource(tmp), in, null).iterator().next();
            assertNotNull(key, "No key pair parsed");
            assertKeyPairEquals("Mismatched recovered keys", testKey, key);
            assertTrue(compare(key, testKey), "Keys should be equal");
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void writePrivateKeyEncryptedAesCbc128(TestData data) throws Exception {
        final KeyPair testKey = generateKey(data);
        Path tmp = getTemporaryOutputFile();
        try (ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            OpenSSHKeyEncryptionContext options = new OpenSSHKeyEncryptionContext();
            options.setPassword("nonsense");
            options.setCipherName("AES");
            options.setCipherMode("CBC");
            options.setCipherType("128");
            OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(testKey, "a comment", options, out);
            writeToFile(tmp, out.toByteArray());
        }
        try (InputStream in = Files.newInputStream(tmp)) {
            KeyPair key = SecurityUtils
                    .loadKeyPairIdentities(null, new PathResource(tmp),
                            in, FilePasswordProvider.of("nonsense"))
                    .iterator().next();
            assertNotNull(key, "No key pair parsed");
            assertKeyPairEquals("Mismatched recovered keys", testKey, key);
            assertTrue(compare(key, testKey), "Keys should be equal");
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void writePrivateKeyEncryptedAesCtr256(TestData data) throws Exception {
        final KeyPair testKey = generateKey(data);
        Path tmp = getTemporaryOutputFile();
        try (ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            OpenSSHKeyEncryptionContext options = new OpenSSHKeyEncryptionContext();
            options.setPassword("nonsense");
            options.setCipherName("AES");
            options.setCipherMode("CTR");
            options.setCipherType("256");
            OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(testKey, "a comment", options, out);
            writeToFile(tmp, out.toByteArray());
        }
        try (InputStream in = Files.newInputStream(tmp)) {
            KeyPair key = SecurityUtils
                    .loadKeyPairIdentities(null, new PathResource(tmp),
                            in, FilePasswordProvider.of("nonsense"))
                    .iterator().next();
            assertNotNull(key, "No key pair parsed");
            assertKeyPairEquals("Mismatched recovered keys", testKey, key);
            assertTrue(compare(key, testKey), "Keys should be equal");
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void writePrivateKeyEncryptedWrongPassword(TestData data) throws Exception {
        final KeyPair testKey = generateKey(data);
        Path tmp = getTemporaryOutputFile();
        try (ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            OpenSSHKeyEncryptionContext options = new OpenSSHKeyEncryptionContext();
            options.setPassword("nonsense");
            options.setCipherName("AES");
            options.setCipherMode("CTR");
            options.setCipherType("256");
            OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(testKey, "a comment", options, out);
            writeToFile(tmp, out.toByteArray());
        }
        try (InputStream in = Files.newInputStream(tmp)) {
            SecurityUtils.loadKeyPairIdentities(null,
                    new PathResource(tmp), in,
                    FilePasswordProvider.of("wrong"));
            fail("Expected an exception");
        } catch (StreamCorruptedException | GeneralSecurityException e) {
            // Expected
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void writePrivateKeyEncryptedNoPassword(TestData data) throws Exception {
        final KeyPair testKey = generateKey(data);
        Path tmp = getTemporaryOutputFile();
        try (ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            OpenSSHKeyEncryptionContext options = new OpenSSHKeyEncryptionContext();
            options.setPassword("nonsense");
            options.setCipherName("AES");
            options.setCipherMode("CTR");
            options.setCipherType("256");
            OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(testKey, "a comment", options, out);
            writeToFile(tmp, out.toByteArray());
        }
        try (InputStream in = Files.newInputStream(tmp)) {
            assertThrows(GeneralSecurityException.class,
                    () -> SecurityUtils.loadKeyPairIdentities(null,
                            new PathResource(tmp), in, null));
        }
    }

    private void checkPublicKey(KeyPair testKey, Path tmp, String comment) throws Exception {
        List<AuthorizedKeyEntry> keysRead = AuthorizedKeyEntry.readAuthorizedKeys(tmp);
        assertEquals(1, keysRead.size(), "Unexpected list size");
        AuthorizedKeyEntry entry = keysRead.get(0);
        String readComment = entry.getComment();
        if (comment == null || comment.isEmpty()) {
            assertTrue(readComment == null || readComment.isEmpty(), "Unexpected comment: " + readComment);
        } else {
            assertEquals(comment, readComment, "Unexpected comment");
        }
        PublicKey pubKey = entry.resolvePublicKey(null,
                PublicKeyEntryResolver.IGNORING);
        assertTrue(KeyUtils.compareKeys(testKey.getPublic(), pubKey),
                "keys don't match");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void writePublicKeyWithComment(TestData data) throws Exception {
        final KeyPair testKey = generateKey(data);
        Path tmp = getTemporaryOutputFile();
        try (OutputStream out = Files.newOutputStream(tmp)) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePublicKey(testKey, "a comment", out);
        }
        checkPublicKey(testKey, tmp, "a comment");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void writePublicKeyWithMultilineComment(TestData data) throws Exception {
        final KeyPair testKey = generateKey(data);
        Path tmp = getTemporaryOutputFile();
        try (OutputStream out = Files.newOutputStream(tmp)) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePublicKey(testKey,
                    "a comment" + System.lineSeparator() + "second line", out);
        }
        assertEquals(1,
                Files.readAllLines(tmp).size(),
                "Unexpected number of lines");
        checkPublicKey(testKey, tmp, "a comment");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void writePublicKeyNoComment(TestData data) throws Exception {
        final KeyPair testKey = generateKey(data);
        Path tmp = getTemporaryOutputFile();
        try (OutputStream out = Files.newOutputStream(tmp)) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePublicKey(testKey, null, out);
        }
        checkPublicKey(testKey, tmp, null);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void writePublicKeyEmptyComment(TestData data) throws Exception {
        final KeyPair testKey = generateKey(data);
        Path tmp = getTemporaryOutputFile();
        try (OutputStream out = Files.newOutputStream(tmp)) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePublicKey(testKey, "", out);
        }
        checkPublicKey(testKey, tmp, null);
    }

    private Path getTemporaryOutputFile(String suffix) throws IOException {
        Path dir = createTempClassFolder();
        String testName = getCurrentTestName();
        int pos = testName.indexOf('[');
        String fileName;
        if (pos > 0) {
            String baseName = testName.substring(0, pos);
            String paramName = testName.substring(pos + 1, testName.length() - 1);
            fileName = baseName + "-" + paramName.replace('(', '-').replace(")", "").trim();
        } else {
            fileName = testName;
        }
        if (suffix != null) {
            fileName += suffix;
        }
        Path file = dir.resolve(fileName);
        Files.deleteIfExists(file);
        return file;
    }

    private Path getTemporaryOutputFile() throws IOException {
        return getTemporaryOutputFile(null);
    }

    private static class TestData {

        final String algorithm;

        final int keySize;

        TestData(String algorithm, int keySize) {
            this.algorithm = algorithm;
            this.keySize = keySize;
        }

        @Override
        public String toString() {
            if (keySize > 0) {
                return algorithm + '-' + keySize;
            }
            return algorithm;
        }
    }
}
