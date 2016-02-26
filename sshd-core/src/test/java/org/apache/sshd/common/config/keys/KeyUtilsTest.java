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

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Date;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.digest.BaseDigest;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.digest.DigestFactory;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.Pair;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.Assume;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class KeyUtilsTest extends BaseTestSupport {
    public KeyUtilsTest() {
        super();
    }

    @Test
    public void testGenerateRSAKeyPairs() throws GeneralSecurityException {
        GeneralSecurityException err = null;
        for (Integer size : RSA_SIZES) {
            int keySize = size.intValue();
            try {
                KeyPair kp = generateKeyPair(KeyPairProvider.SSH_RSA, keySize);
                testKeyPairCloning(KeyPairProvider.SSH_RSA, keySize, kp);
            } catch (GeneralSecurityException e) {
                err = GenericUtils.accumulateException(err, e);
            }
        }

        if (err != null) {
            throw err;
        }
    }

    @Test
    public void testGenerateDSSKeyPairs() throws GeneralSecurityException {
        GeneralSecurityException err = null;
        for (Integer size : DSS_SIZES) {
            int keySize = size.intValue();
            try {
                KeyPair kp = generateKeyPair(KeyPairProvider.SSH_DSS, keySize);
                testKeyPairCloning(KeyPairProvider.SSH_DSS, keySize, kp);
            } catch (GeneralSecurityException e) {
                err = GenericUtils.accumulateException(err, e);
            }
        }

        if (err != null) {
            throw err;
        }
    }

    @Test
    public void testGenerateECDSAKeyPairs() throws GeneralSecurityException {
        Assume.assumeTrue("No ECC support", SecurityUtils.hasEcc());

        GeneralSecurityException err = null;
        for (ECCurves curve : ECCurves.VALUES) {
            if (!curve.isSupported()) {
                System.out.println("Skip unsupported curve=" + curve.getName());
                continue;
            }

            String keyType = curve.getKeyType();
            int keySize = curve.getKeySize();
            try {
                KeyPair kp = generateKeyPair(keyType, keySize);
                testKeyPairCloning(keyType, keySize, kp);
            } catch (GeneralSecurityException e) {
                err = GenericUtils.accumulateException(err, e);
            }
        }

        if (err != null) {
            throw err;
        }
    }

    @Test
    public void testGenerateFingerPrintOnException() {
        for (final DigestFactory info : BuiltinDigests.VALUES) {
            if (!info.isSupported()) {
                System.out.println("Skip unsupported digest: " + info.getAlgorithm());
                continue;
            }

            final Exception thrown = new DigestException(info.getAlgorithm() + ":" + info.getBlockSize());
            final Digest digest = new BaseDigest(info.getAlgorithm(), info.getBlockSize()) {
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
            assertEquals("Mismatched fingerprint for " + thrown.getMessage(), expected, actual);
        }
    }

    @Test
    public void testGenerateDefaultFingerprintDigest() {
        final DigestFactory defaultValue = KeyUtils.getDefaultFingerPrintFactory();
        assertNotNull("No current default fingerprint digest factory", defaultValue);
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
                assertEquals("Mismatched fingerprint for digest=" + f.getName(), expected, actual);
            }
        } finally {
            KeyUtils.setDefaultFingerPrintFactory(defaultValue); // restore the original
        }
    }

    @Test   // see SSHD-606
    public void testValidateStrictKeyFilePermissions() throws IOException {
        Path file = getTempTargetRelativeFile(getClass().getSimpleName(), getCurrentTestName());
        outputDebugMessage("%s deletion result=%s", file, Files.deleteIfExists(file));
        assertNull("Unexpected violation for non-existent file: " + file, KeyUtils.validateStrictKeyFilePermissions(file));

        assertHierarchyTargetFolderExists(file.getParent());
        try (OutputStream output = Files.newOutputStream(file)) {
            output.write((getClass().getName() + "#" + getCurrentTestName() + "@" + new Date(System.currentTimeMillis())).getBytes(StandardCharsets.UTF_8));
        }

        Collection<PosixFilePermission> perms = IoUtils.getPermissions(file);
        if (GenericUtils.isEmpty(perms)) {
            assertNull("Unexpected violation for no permissions file: " + file, KeyUtils.validateStrictKeyFilePermissions(file));
        } else if (OsUtils.isUNIX()) {
            Pair<String, Object> violation = null;
            for (PosixFilePermission p : KeyUtils.STRICTLY_PROHIBITED_FILE_PERMISSION) {
                if (perms.contains(p)) {
                    violation = KeyUtils.validateStrictKeyFilePermissions(file);
                    assertNotNull("Unexpected success for permission=" + p + " of file " + file + " permissions=" + perms, violation);
                    break;
                }
            }

            if (violation == null) {    // we expect a failure since the parent does not have the necessary permissions
                assertNotNull("Unexpected UNIX success for file " + file + " permissions=" + perms, KeyUtils.validateStrictKeyFilePermissions(file));
            }
        } else {
            assertNull("Unexpected Windows violation for file " + file + " permissions=" + perms, KeyUtils.validateStrictKeyFilePermissions(file));
        }
    }

    private static KeyPair generateKeyPair(String keyType, int keySize) throws GeneralSecurityException {
        try {
            outputDebugMessage("generateKeyPair(%s)[%d]", keyType, keySize);
            return KeyUtils.generateKeyPair(keyType, keySize);
        } catch (GeneralSecurityException e) {
            System.err.println("Failed (" + e.getClass().getSimpleName() + ") to generate key-pair for " + keyType + "/" + keySize + ": " + e.getMessage());
            throw e;
        }
    }

    @SuppressWarnings("checkstyle:avoidnestedblocks")
    private static void testKeyPairCloning(String keyType, int keySize, KeyPair kp) throws GeneralSecurityException {
        String prefix = keyType + "[" + keySize + "]";
        outputDebugMessage("testKeyPairCloning(%s)", prefix);

        KeyPair cloned = KeyUtils.cloneKeyPair(keyType, kp);
        assertNotSame(prefix + ": Key pair not cloned", kp, cloned);
        assertTrue(prefix + ": Cloned pair not equals", KeyUtils.compareKeyPairs(kp, cloned));

        {
            PublicKey k1 = kp.getPublic();
            PublicKey k2 = cloned.getPublic();
            assertNotSame(prefix + ": Public key not cloned", k1, k2);
            assertTrue(prefix + ": Cloned public key not equals", KeyUtils.compareKeys(k1, k2));

            String f1 = KeyUtils.getFingerPrint(k1);
            String f2 = KeyUtils.getFingerPrint(k2);
            assertEquals(prefix + ": Mismatched fingerprints", f1, f2);
        }

        {
            PrivateKey k1 = kp.getPrivate();
            PrivateKey k2 = cloned.getPrivate();
            assertNotSame(prefix + ": Private key not cloned", k1, k2);
            assertTrue(prefix + ": Cloned private key not equals", KeyUtils.compareKeys(k1, k2));
        }
    }
}
