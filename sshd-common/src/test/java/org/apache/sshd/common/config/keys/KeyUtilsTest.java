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
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Assume;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class KeyUtilsTest extends JUnitTestSupport {
    public KeyUtilsTest() {
        super();
    }

    @Test
    public void testGenerateFingerPrintOnException() {
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
            assertEquals("Mismatched fingerprint for " + thrown.getMessage(), expected, actual);
        }
    }

    @Test
    public void testGenerateDefaultFingerprintDigest() {
        DigestFactory defaultValue = KeyUtils.getDefaultFingerPrintFactory();
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

    @Test // see SSHD-606
    public void testValidateStrictKeyFilePermissions() throws IOException {
        Assume.assumeTrue("Test does not always work on Windows", !OsUtils.isWin32());

        Path file = getTempTargetRelativeFile(getClass().getSimpleName(), getCurrentTestName());
        outputDebugMessage("%s deletion result=%s", file, Files.deleteIfExists(file));
        assertNull("Unexpected violation for non-existent file: " + file, KeyUtils.validateStrictKeyFilePermissions(file));

        assertHierarchyTargetFolderExists(file.getParent());
        try (OutputStream output = Files.newOutputStream(file)) {
            output.write((getClass().getName() + "#" + getCurrentTestName() + "@" + new Date(System.currentTimeMillis()))
                    .getBytes(StandardCharsets.UTF_8));
        }

        Collection<PosixFilePermission> perms = IoUtils.getPermissions(file);
        if (GenericUtils.isEmpty(perms)) {
            assertNull("Unexpected violation for no permissions file: " + file,
                    KeyUtils.validateStrictKeyFilePermissions(file));
        } else if (OsUtils.isUNIX()) {
            Map.Entry<String, Object> violation = null;
            for (PosixFilePermission p : KeyUtils.STRICTLY_PROHIBITED_FILE_PERMISSION) {
                if (perms.contains(p)) {
                    violation = KeyUtils.validateStrictKeyFilePermissions(file);
                    assertNotNull("Unexpected success for permission=" + p + " of file " + file + " permissions=" + perms,
                            violation);
                    break;
                }
            }

            if (violation == null) { // we expect a failure since the parent does not have the necessary permissions
                assertNotNull("Unexpected UNIX success for file " + file + " permissions=" + perms,
                        KeyUtils.validateStrictKeyFilePermissions(file));
            }
        } else {
            assertNull("Unexpected Windows violation for file " + file + " permissions=" + perms,
                    KeyUtils.validateStrictKeyFilePermissions(file));
        }
    }

    @Test // see SSHD-895
    public void testRSAKeyTypeAliases() {
        for (String alias : new String[] { KeyUtils.RSA_SHA256_KEY_TYPE_ALIAS, KeyUtils.RSA_SHA512_KEY_TYPE_ALIAS }) {
            assertEquals("Mismatched canonical name for " + alias, KeyPairProvider.SSH_RSA,
                    KeyUtils.getCanonicalKeyType(alias));
        }
    }
}
