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

package org.apache.sshd.common.config.keys;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.DigestException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import org.apache.sshd.common.digest.BaseDigest;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.digest.DigestFactory;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class KeyUtilsTest extends JUnitTestSupport {

    @TempDir
    protected File testDir;

    public KeyUtilsTest() {
        super();
    }

    @Test
    void generateFingerPrintOnException() {
        for (DigestFactory info : BuiltinDigests.VALUES) {
            if (!info.isSupported()) {
                System.out.println("Skip unsupported digest: " + info.getAlgorithm());
                continue;
            }

            Exception thrown = new DigestException(info.getAlgorithm() + ":" + info.getBlockSize());
            Digest digest = new BaseDigest(info.getAlgorithm(), info.getBlockSize()) {
                @Override
                public byte[] digest() throws Exception {
                    throw thrown;
                }
            };
            String actual = KeyUtils.getFingerPrint(new DigestFactory() {
                @Override
                public String getName() {
                    return getCurrentTestName();
                }

                @Override
                public String getAlgorithm() {
                    return digest.getAlgorithm();
                }

                @Override
                public boolean isSupported() {
                    return info.isSupported();
                }

                @Override
                public int getBlockSize() {
                    return info.getBlockSize();
                }

                @Override
                public Digest create() {
                    return digest;
                }
            }, getCurrentTestName());
            String expected = thrown.getClass().getSimpleName();
            assertEquals(expected, actual, "Mismatched fingerprint for " + thrown.getMessage());
        }
    }

    @Test
    void generateDefaultFingerprintDigest() {
        DigestFactory defaultValue = KeyUtils.getDefaultFingerPrintFactory();
        assertNotNull(defaultValue, "No current default fingerprint digest factory");
        try {
            for (DigestFactory f : BuiltinDigests.VALUES) {
                if (!f.isSupported()) {
                    System.out.println("Skip unsupported digest=" + f.getAlgorithm());
                    continue;
                }

                KeyUtils.setDefaultFingerPrintFactory(f);

                String data = getClass().getName() + "#" + getCurrentTestName() + "(" + f.getName() + ")";
                String expected = KeyUtils.getFingerPrint(f, data);
                String actual = KeyUtils.getFingerPrint(data);
                assertEquals(expected, actual, "Mismatched fingerprint for digest=" + f.getName());
            }
        } finally {
            KeyUtils.setDefaultFingerPrintFactory(defaultValue); // restore the original
        }
    }

    // see SSHD-606
    @Test
    void validateStrictKeyFilePermissions() throws IOException {
        Assumptions.assumeTrue(!OsUtils.isWin32(), "Test does not always work on Windows");

        Path file = getTempTargetRelativeFile(getClass().getSimpleName(), getCurrentTestName());
        outputDebugMessage("%s deletion result=%s", file, Files.deleteIfExists(file));
        assertNull(KeyUtils.validateStrictKeyFilePermissions(file), "Unexpected violation for non-existent file: " + file);

        assertHierarchyTargetFolderExists(file.getParent());
        try (OutputStream output = Files.newOutputStream(file)) {
            output.write((getClass().getName() + "#" + getCurrentTestName() + "@" + new Date(System.currentTimeMillis()))
                    .getBytes(StandardCharsets.UTF_8));
        }

        Collection<PosixFilePermission> perms = IoUtils.getPermissions(file);
        if (GenericUtils.isEmpty(perms)) {
            assertNull(KeyUtils.validateStrictKeyFilePermissions(file),
                    "Unexpected violation for no permissions file: " + file);
        } else if (OsUtils.isUNIX()) {
            Map.Entry<String, Object> violation = null;
            for (PosixFilePermission p : KeyUtils.STRICTLY_PROHIBITED_FILE_PERMISSION) {
                if (perms.contains(p)) {
                    violation = KeyUtils.validateStrictKeyFilePermissions(file);
                    assertNotNull(violation,
                            "Unexpected success for permission=" + p + " of file " + file + " permissions=" + perms);
                    break;
                }
            }

            if (violation == null) { // we expect a failure since the parent does not have the necessary permissions
                assertNotNull(KeyUtils.validateStrictKeyFilePermissions(file),
                        "Unexpected UNIX success for file " + file + " permissions=" + perms);
            }
        } else {
            assertNull(KeyUtils.validateStrictKeyFilePermissions(file),
                    "Unexpected Windows violation for file " + file + " permissions=" + perms);
        }
    }

    // see SSHD-895
    @Test
    void rsaKeyTypeAliases() {
        for (String alias : new String[] { KeyUtils.RSA_SHA256_KEY_TYPE_ALIAS, KeyUtils.RSA_SHA512_KEY_TYPE_ALIAS }) {
            assertEquals(KeyPairProvider.SSH_RSA,
                    KeyUtils.getCanonicalKeyType(alias),
                    "Mismatched canonical name for " + alias);
        }
    }

    @Test
    void loadPublicKey() throws Exception {
        Path testFile = File.createTempFile("junit", null, testDir).toPath();
        try (InputStream testContent = this.getClass().getClassLoader().getResourceAsStream(
                this.getClass().getPackage().getName().replace('.', '/') + "/loader/openssh/RSA-KeyPair.pub")) {
            Files.copy(testContent, testFile, StandardCopyOption.REPLACE_EXISTING);
        }
        PublicKey key = KeyUtils.loadPublicKey(testFile);
        assertNotNull(key);
        assertEquals("ssh-rsa", KeyUtils.getKeyType(key));
    }

    @Test
    void loadPublicKeyNonExisting() throws Exception {
        Path testFile = testDir.toPath().resolve("does_not_exist");
        assertFalse(Files.exists(testFile, LinkOption.NOFOLLOW_LINKS));
        assertThrows(IOException.class, () -> KeyUtils.loadPublicKey(testFile));
    }

    @Test
    void loadPublicKeyEmpty() throws Exception {
        Path testFile = File.createTempFile("junit", null, testDir).toPath();
        PublicKey key = KeyUtils.loadPublicKey(testFile);
        assertNull(key);
    }

    @Test
    void loadPublicKeyMultiple() throws Exception {
        Path testFile = File.createTempFile("junit", null, testDir).toPath();
        byte[] data;
        try (InputStream testContent = this.getClass().getClassLoader().getResourceAsStream(
                this.getClass().getPackage().getName().replace('.', '/') + "/loader/openssh/RSA-KeyPair.pub")) {
            data = IoUtils.toByteArray(testContent);
        }
        int size = data.length;
        data = Arrays.copyOf(data, 2 * size + 1);
        data[size] = '\n';
        System.arraycopy(data, 0, data, size + 1, size);
        try (ByteArrayInputStream in = new ByteArrayInputStream(data)) {
            Files.copy(in, testFile, StandardCopyOption.REPLACE_EXISTING);
        }
        assertThrows(Exception.class, () -> KeyUtils.loadPublicKey(testFile));
    }

    @Test
    void loadPublicKeyCorrupt() throws Exception {
        Path testFile = File.createTempFile("junit", null, testDir).toPath();
        byte[] data = new byte[42];
        Arrays.fill(data, (byte) 'a');
        Files.write(testFile, data);
        assertEquals(42, Files.size(testFile));
        assertThrows(Exception.class, () -> KeyUtils.loadPublicKey(testFile));
    }
}
