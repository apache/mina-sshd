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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.io.SecureByteArrayOutputStream;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import net.i2p.crypto.eddsa.EdDSAKey;
import net.i2p.crypto.eddsa.spec.EdDSAGenParameterSpec;

@RunWith(Parameterized.class)
public class OpenSSHKeyPairResourceWriterTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    private static class TestData {
        public final String algorithm;

        public final String provider;

        public final int keySize;

        public final AlgorithmParameterSpec spec;

        public TestData(String algorithm, int keySize,
                AlgorithmParameterSpec spec) {
            this(algorithm, null, keySize, spec);
        }

        public TestData(String algorithm, String provider, int keySize,
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

    @Parameters(name = "{0}")
    public static Object[] getParams() {
        List<TestData> result = new ArrayList<>();
        result.add(new TestData("RSA", 1024, null));
        result.add(new TestData("RSA", 2048, null));
        result.add(new TestData("DSA", 1024, null));
        result.add(
                new TestData("ECDSA", 256,
                        new ECGenParameterSpec("secp256r1")));
        result.add(
                new TestData("ECDSA", 384,
                        new ECGenParameterSpec("secp384r1")));
        result.add(
                new TestData("ECDSA", 521,
                        new ECGenParameterSpec("secp521r1")));
        result.add(new TestData("EDDSA", "EdDSA", 25519,
                new EdDSAGenParameterSpec("Ed25519")));
        // Note: BC also has an EDDSA provider, but that one returns
        // "Ed25519" as algorithm from its keys, while the one in
        // net.i2p.crypto.eddsa gives keys with "EDDSA" as algorithm.
        // sshd handles only the latter.
        return result.toArray();
    }

    @Parameter
    public TestData data;

    private KeyPair testKey;

    private OpenSSHKeyPairResourceWriter writer = new OpenSSHKeyPairResourceWriter();

    @Before
    public void generateKey() throws Exception {
        KeyPairGenerator generator;
        if (data.provider == null) {
            generator = KeyPairGenerator.getInstance(data.algorithm);
        } else {
            generator = KeyPairGenerator.getInstance(data.algorithm,
                    data.provider);
        }
        if (data.spec != null) {
            generator.initialize(data.spec);
        } else {
            generator.initialize(data.keySize);
        }
        testKey = generator.generateKeyPair();
    }

    private boolean compare(KeyPair a, KeyPair b) {
        if ("EDDSA".equals(data.algorithm)) {
            // Bug in net.i2p.crypto.eddsa and in sshd? Both also compare the
            // seed of the private key, but for a generated key, this is some
            // random value, while it is all zeroes for a key read from a file.
            return KeyUtils.compareKeys(a.getPublic(), b.getPublic())
                    && Objects.equals(((EdDSAKey) a.getPrivate()).getParams(),
                            ((EdDSAKey) b.getPrivate()).getParams());
        }
        // Compares both public and private keys.
        return KeyUtils.compareKeyPairs(a, b);
    }

    private static void writeToFile(File file, byte[] sensitiveData)
            throws IOException {
        try (ByteChannel out = Files.newByteChannel(file.toPath(),
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
    public void privateNoEncryption() throws Exception {
        File tmp = folder.newFile();
        try (SecureByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            writer.writePrivateKey(testKey, "a comment", null, out);
            writeToFile(tmp, out.toByteArray());
        }
        try (InputStream in = Files.newInputStream(tmp.toPath())) {
            KeyPair key = SecurityUtils.loadKeyPairIdentities(null,
                    new PathResource(tmp.toPath()), in, null).iterator().next();
            assertNotNull(key);
            assertTrue("Keys should be equal", compare(key, testKey));
        }
    }

    @Test
    public void privateNoPassword() throws Exception {
        File tmp = folder.newFile();
        OpenSSHKeyEncryptionContext options = new OpenSSHKeyEncryptionContext();
        try (SecureByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            writer.writePrivateKey(testKey, "a comment", options, out);
            writeToFile(tmp, out.toByteArray());
        } finally {
            options.clear();
        }
        try (InputStream in = Files.newInputStream(tmp.toPath())) {
            KeyPair key = SecurityUtils.loadKeyPairIdentities(null,
                    new PathResource(tmp.toPath()), in, null).iterator().next();
            assertNotNull(key);
            assertTrue("Keys should be equal", compare(key, testKey));
        }
    }

    @Test
    public void privateEncryptedAesCbc128() throws Exception {
        File tmp = folder.newFile();
        OpenSSHKeyEncryptionContext options = new OpenSSHKeyEncryptionContext();
        try (SecureByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            options.setPassphrase("nonsense".toCharArray());
            options.setCipherName("AES");
            options.setCipherMode("CBC");
            options.setCipherType("128");
            writer.writePrivateKey(testKey, "a comment", options, out);
            writeToFile(tmp, out.toByteArray());
        } finally {
            options.clear();
        }
        try (InputStream in = Files.newInputStream(tmp.toPath())) {
            KeyPair key = SecurityUtils
                    .loadKeyPairIdentities(null, new PathResource(tmp.toPath()),
                            in, FilePasswordProvider.of("nonsense"))
                    .iterator().next();
            assertNotNull(key);
            assertTrue("Keys should be equal", compare(key, testKey));
        }
    }

    @Test
    public void privateEncryptedAesCtr256() throws Exception {
        File tmp = folder.newFile();
        OpenSSHKeyEncryptionContext options = new OpenSSHKeyEncryptionContext();
        try (SecureByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            options.setPassphrase("nonsense".toCharArray());
            options.setCipherName("AES");
            options.setCipherMode("CTR");
            options.setCipherType("256");
            writer.writePrivateKey(testKey, "a comment", options, out);
            writeToFile(tmp, out.toByteArray());
        } finally {
            options.clear();
        }
        try (InputStream in = Files.newInputStream(tmp.toPath())) {
            KeyPair key = SecurityUtils
                    .loadKeyPairIdentities(null, new PathResource(tmp.toPath()),
                            in, FilePasswordProvider.of("nonsense"))
                    .iterator().next();
            assertNotNull(key);
            assertTrue("Keys should be equal", compare(key, testKey));
        }
    }

    @Test
    public void privateEncryptedWrongPassword() throws Exception {
        File tmp = folder.newFile();
        OpenSSHKeyEncryptionContext options = new OpenSSHKeyEncryptionContext();
        try (SecureByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            options.setPassphrase("nonsense".toCharArray());
            options.setCipherName("AES");
            options.setCipherMode("CTR");
            options.setCipherType("256");
            writer.writePrivateKey(testKey, "a comment", options, out);
            writeToFile(tmp, out.toByteArray());
        } finally {
            options.clear();
        }
        try (InputStream in = Files.newInputStream(tmp.toPath())) {
            SecurityUtils.loadKeyPairIdentities(null,
                    new PathResource(tmp.toPath()), in,
                    FilePasswordProvider.of("wrong"));
            fail("Expected an exception");
        } catch (StreamCorruptedException | GeneralSecurityException e) {
            // Expected
        }
    }

    @Test
    public void privateEncryptedNoPassword() throws Exception {
        File tmp = folder.newFile();
        OpenSSHKeyEncryptionContext options = new OpenSSHKeyEncryptionContext();
        try (SecureByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            options.setPassphrase("nonsense".toCharArray());
            options.setCipherName("AES");
            options.setCipherMode("CTR");
            options.setCipherType("256");
            writer.writePrivateKey(testKey, "a comment", options, out);
            writeToFile(tmp, out.toByteArray());
        } finally {
            options.clear();
        }
        try (InputStream in = Files.newInputStream(tmp.toPath())) {
            assertThrows(GeneralSecurityException.class,
                    () -> SecurityUtils.loadKeyPairIdentities(null,
                            new PathResource(tmp.toPath()), in, null));
        }
    }

    private void checkPublicKey(File tmp, String comment) throws Exception {
        List<AuthorizedKeyEntry> keysRead = AuthorizedKeyEntry
                .readAuthorizedKeys(tmp.toPath());
        assertEquals("Unexpected list size", 1, keysRead.size());
        AuthorizedKeyEntry entry = keysRead.get(0);
        String readComment = entry.getComment();
        if (comment == null || comment.isEmpty()) {
            assertTrue("Unexpected comment", readComment == null || readComment.isEmpty());
        } else {
            assertEquals("Unexpected comment", comment, readComment);
        }
        PublicKey pubKey = entry.resolvePublicKey(null,
                PublicKeyEntryResolver.IGNORING);
        assertTrue("keys don't match",
                KeyUtils.compareKeys(testKey.getPublic(), pubKey));
    }

    @Test
    public void publicWithComment() throws Exception {
        File tmp = folder.newFile();
        try (OutputStream out = new FileOutputStream(tmp)) {
            writer.writePublicKey(testKey, "a comment", out);
        }
        checkPublicKey(tmp, "a comment");
    }

    @Test
    public void publicWithMultilineComment() throws Exception {
        File tmp = folder.newFile();
        try (OutputStream out = new FileOutputStream(tmp)) {
            writer.writePublicKey(testKey,
                    "a comment" + System.lineSeparator() + "second line", out);
        }
        assertEquals("Unexpected number of lines", 1,
                Files.readAllLines(tmp.toPath()).size());
        checkPublicKey(tmp, "a comment");
    }

    @Test
    public void publicNoComment() throws Exception {
        File tmp = folder.newFile();
        try (OutputStream out = new FileOutputStream(tmp)) {
            writer.writePublicKey(testKey, null, out);
        }
        checkPublicKey(tmp, null);
    }

    @Test
    public void publicEmptyComment() throws Exception {
        File tmp = folder.newFile();
        try (OutputStream out = new FileOutputStream(tmp)) {
            writer.writePublicKey(testKey, "", out);
        }
        checkPublicKey(tmp, null);
    }
}
