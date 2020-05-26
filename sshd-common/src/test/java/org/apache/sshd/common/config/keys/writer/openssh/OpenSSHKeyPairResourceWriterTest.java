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
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import net.i2p.crypto.eddsa.spec.EdDSAGenParameterSpec;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.io.SecureByteArrayOutputStream;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class OpenSSHKeyPairResourceWriterTest extends JUnitTestSupport {
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    private final TestData data;
    private KeyPair testKey;

    public OpenSSHKeyPairResourceWriterTest(TestData data) {
        this.data = data;
    }

    @Parameters(name = "{0}")
    public static Collection<Object[]> parameters() {
        List<TestData> result = new ArrayList<>();
        result.add(new TestData("RSA", 1024, null));
        result.add(new TestData("RSA", 2048, null));
        result.add(new TestData("DSA", 1024, null));
        if (SecurityUtils.isECCSupported()) {
            result.add(
                    new TestData(
                            "ECDSA", 256,
                            new ECGenParameterSpec("secp256r1")));
            result.add(
                    new TestData(
                            "ECDSA", 384,
                            new ECGenParameterSpec("secp384r1")));
            result.add(
                    new TestData(
                            "ECDSA", 521,
                            new ECGenParameterSpec("secp521r1")));
        }
        if (SecurityUtils.isEDDSACurveSupported()) {
            // Note: BC also has an EDDSA provider, but that one returns
            // "Ed25519" as algorithm from its keys, while the one in
            // net.i2p.crypto.eddsa gives keys with "EDDSA" as algorithm.
            // sshd handles only the latter.
            result.add(new TestData(
                    "EDDSA", "EdDSA", 25519,
                    new EdDSAGenParameterSpec("Ed25519")));
        }

        return parameterize(result);
    }

    @Before
    public void setUp() throws Exception {
        KeyPairGenerator generator;
        if (data.provider == null) {
            generator = KeyPairGenerator.getInstance(data.algorithm);
        } else {
            generator = KeyPairGenerator.getInstance(data.algorithm, data.provider);
        }

        if (data.spec != null) {
            generator.initialize(data.spec);
        } else {
            generator.initialize(data.keySize);
        }
        testKey = generator.generateKeyPair();
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

    @Test
    public void testFileRoundtripNoEncryption() throws Exception {
        Path tmp = getTemporaryOutputFile();
        try (SecureByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(testKey, "a comment", null, out);
            writeToFile(tmp, out.toByteArray());
        }
        try (InputStream in = Files.newInputStream(tmp)) {
            KeyPair key = SecurityUtils.loadKeyPairIdentities(null,
                    new PathResource(tmp), in, null).iterator().next();
            assertNotNull("No key pair parsed", key);
            assertKeyPairEquals("Mismatched recovered keys", testKey, key);
            assertTrue("Keys should be equal", compare(key, testKey));
            Path tmp2 = getTemporaryOutputFile("again");
            try (SecureByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
                OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(key, "a comment", null, out);
                writeToFile(tmp2, out.toByteArray());
            }
            try (InputStream in2 = Files.newInputStream(tmp2)) {
                KeyPair key2 = SecurityUtils.loadKeyPairIdentities(null,
                        new PathResource(tmp2), in2, null).iterator().next();
                assertNotNull("No key pair parsed", key2);
                assertKeyPairEquals("Mismatched recovered keys", testKey, key2);
                assertTrue("Keys should be equal", compare(key2, testKey));

                assertKeyPairEquals("Mismatched recovered keys", key, key2);
                assertTrue("Keys should be equal", compare(key2, key));
            }
        }
    }

    @Test
    public void testFileRoundtripWithEncryption() throws Exception {
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
            assertNotNull("No key pair parsed", key);
            assertKeyPairEquals("Mismatched recovered keys", testKey, key);
            assertTrue("Keys should be equal", compare(key, testKey));
            Path tmp2 = getTemporaryOutputFile("again");
            try (ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
                OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(key, "a comment", options, out);
                writeToFile(tmp2, out.toByteArray());
            }
            try (InputStream in2 = Files.newInputStream(tmp2)) {
                KeyPair key2 = SecurityUtils.loadKeyPairIdentities(null,
                        new PathResource(tmp2), in2, FilePasswordProvider.of("nonsense")).iterator().next();
                assertNotNull("No key pair parsed", key2);
                assertKeyPairEquals("Mismatched recovered keys", testKey, key2);
                assertTrue("Keys should be equal", compare(key2, testKey));

                assertKeyPairEquals("Mismatched recovered keys", key, key2);
                assertTrue("Keys should be equal", compare(key2, key));
            }
        }
    }

    @Test
    public void testFileRoundtripAsymmetric() throws Exception {
        // Write first unencrypted, then encrypted. read both and compare.
        Path tmp = getTemporaryOutputFile();
        try (ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(testKey, "a comment", null, out);
            writeToFile(tmp, out.toByteArray());
        }
        try (InputStream in = Files.newInputStream(tmp)) {
            KeyPair key = SecurityUtils.loadKeyPairIdentities(null,
                    new PathResource(tmp), in, null).iterator().next();
            assertNotNull("No key pair parsed", key);
            assertKeyPairEquals("Mismatched recovered keys", testKey, key);
            assertTrue("Keys should be equal", compare(key, testKey));
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
                assertNotNull("No key pair parsed", key2);
                assertKeyPairEquals("Mismatched recovered keys", testKey, key2);
                assertTrue("Keys should be equal", compare(key2, testKey));

                assertKeyPairEquals("Mismatched recovered keys", key, key2);
                assertTrue("Keys should be equal", compare(key2, key));
            }
        }
    }

    @Test
    public void testWritePrivateKeyNoEncryption() throws Exception {
        Path tmp = getTemporaryOutputFile();
        try (ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(testKey, "a comment", null, out);
            writeToFile(tmp, out.toByteArray());
        }
        try (InputStream in = Files.newInputStream(tmp)) {
            KeyPair key = SecurityUtils.loadKeyPairIdentities(null,
                    new PathResource(tmp), in, null).iterator().next();
            assertNotNull("No key pair parsed", key);
            assertKeyPairEquals("Mismatched recovered keys", testKey, key);
            assertTrue("Keys should be equal", compare(key, testKey));
        }
    }

    @Test
    public void testWritePrivateKeyNoPassword() throws Exception {
        Path tmp = getTemporaryOutputFile();
        try (ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            OpenSSHKeyEncryptionContext options = new OpenSSHKeyEncryptionContext();
            OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(testKey, "a comment", options, out);
            writeToFile(tmp, out.toByteArray());
        }
        try (InputStream in = Files.newInputStream(tmp)) {
            KeyPair key = SecurityUtils.loadKeyPairIdentities(null,
                    new PathResource(tmp), in, null).iterator().next();
            assertNotNull("No key pair parsed", key);
            assertKeyPairEquals("Mismatched recovered keys", testKey, key);
            assertTrue("Keys should be equal", compare(key, testKey));
        }
    }

    @Test
    public void testWritePrivateKeyEncryptedAesCbc128() throws Exception {
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
            assertNotNull("No key pair parsed", key);
            assertKeyPairEquals("Mismatched recovered keys", testKey, key);
            assertTrue("Keys should be equal", compare(key, testKey));
        }
    }

    @Test
    public void testWritePrivateKeyEncryptedAesCtr256() throws Exception {
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
            assertNotNull("No key pair parsed", key);
            assertKeyPairEquals("Mismatched recovered keys", testKey, key);
            assertTrue("Keys should be equal", compare(key, testKey));
        }
    }

    @Test
    public void testWritePrivateKeyEncryptedWrongPassword() throws Exception {
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

    @Test
    public void testWritePrivateKeyEncryptedNoPassword() throws Exception {
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

    private void checkPublicKey(Path tmp, String comment) throws Exception {
        List<AuthorizedKeyEntry> keysRead = AuthorizedKeyEntry.readAuthorizedKeys(tmp);
        assertEquals("Unexpected list size", 1, keysRead.size());
        AuthorizedKeyEntry entry = keysRead.get(0);
        String readComment = entry.getComment();
        if (comment == null || comment.isEmpty()) {
            assertTrue("Unexpected comment: " + readComment, readComment == null || readComment.isEmpty());
        } else {
            assertEquals("Unexpected comment", comment, readComment);
        }
        PublicKey pubKey = entry.resolvePublicKey(null,
                PublicKeyEntryResolver.IGNORING);
        assertTrue("keys don't match",
                KeyUtils.compareKeys(testKey.getPublic(), pubKey));
    }

    @Test
    public void testWritePublicKeyWithComment() throws Exception {
        Path tmp = getTemporaryOutputFile();
        try (OutputStream out = Files.newOutputStream(tmp)) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePublicKey(testKey, "a comment", out);
        }
        checkPublicKey(tmp, "a comment");
    }

    @Test
    public void testWritePublicKeyWithMultilineComment() throws Exception {
        Path tmp = getTemporaryOutputFile();
        try (OutputStream out = Files.newOutputStream(tmp)) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePublicKey(testKey,
                    "a comment" + System.lineSeparator() + "second line", out);
        }
        assertEquals("Unexpected number of lines", 1,
                Files.readAllLines(tmp).size());
        checkPublicKey(tmp, "a comment");
    }

    @Test
    public void testWritePublicKeyNoComment() throws Exception {
        Path tmp = getTemporaryOutputFile();
        try (OutputStream out = Files.newOutputStream(tmp)) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePublicKey(testKey, null, out);
        }
        checkPublicKey(tmp, null);
    }

    @Test
    public void testWritePublicKeyEmptyComment() throws Exception {
        Path tmp = getTemporaryOutputFile();
        try (OutputStream out = Files.newOutputStream(tmp)) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePublicKey(testKey, "", out);
        }
        checkPublicKey(tmp, null);
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

    @SuppressWarnings("checkstyle:VisibilityModifier")
    private static class TestData {
        public final String algorithm;

        public final String provider;

        public final int keySize;

        public final AlgorithmParameterSpec spec;

        TestData(String algorithm, int keySize,
                 AlgorithmParameterSpec spec) {
            this(algorithm, null, keySize, spec);
        }

        TestData(String algorithm, String provider, int keySize,
                 AlgorithmParameterSpec spec) {
            this.algorithm = algorithm;
            this.provider = provider;
            this.keySize = keySize;
            this.spec = spec;
        }

        @Override
        public String toString() {
            return algorithm + '-' + keySize
                   + (provider == null ? "" : '(' + provider + ')');
        }
    }
}
