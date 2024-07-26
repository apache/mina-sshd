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

package org.apache.sshd.common.util.security;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceLoader;
import org.apache.sshd.common.keyprovider.AbstractResourceKeyPairProvider;
import org.apache.sshd.common.keyprovider.ClassLoadableResourceKeyPairProvider;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
@SuppressWarnings("checkstyle:MethodCount")
public class SecurityUtilsTest extends SecurityUtilsTestSupport {
    private static final String DEFAULT_PASSWORD = "super secret passphrase";
    private static final FilePasswordProvider TEST_PASSWORD_PROVIDER = (session, file, index) -> DEFAULT_PASSWORD;

    public SecurityUtilsTest() {
        super();
    }

    @Test
    void loadEncryptedDESPrivateKey() throws Exception {
        testLoadEncryptedRSAPrivateKey("DES-EDE3");
    }

    @Test
    void loadEncryptedAESPrivateKey() {
        for (BuiltinCiphers c : new BuiltinCiphers[] {
                BuiltinCiphers.aes128cbc, BuiltinCiphers.aes192cbc, BuiltinCiphers.aes256cbc
        }) {
            if (!c.isSupported()) {
                System.out.println("Skip unsupported encryption scheme: " + c.getName());
                continue;
            }

            try {
                testLoadEncryptedRSAPrivateKey("AES-" + c.getKeySize());
            } catch (Exception e) {
                fail("Failed (" + e.getClass().getSimpleName() + " to load key for " + c.getName() + ": " + e.getMessage());
            }
        }
    }

    private KeyPair testLoadEncryptedRSAPrivateKey(String algorithm) throws Exception {
        return testLoadRSAPrivateKey(DEFAULT_PASSWORD.replace(' ', '-') + "-RSA-" + algorithm.toUpperCase() + "-key");
    }

    @Test
    void loadUnencryptedRSAPrivateKey() throws Exception {
        testLoadRSAPrivateKey(getClass().getSimpleName() + "-RSA-KeyPair");
    }

    @Test
    void loadUnencryptedDSSPrivateKey() throws Exception {
        testLoadDSSPrivateKey(getClass().getSimpleName() + "-DSA-KeyPair");
    }

    private KeyPair testLoadDSSPrivateKey(String name) throws Exception {
        return testLoadPrivateKey(name, DSAPublicKey.class, DSAPrivateKey.class);
    }

    @Test
    void loadUnencryptedECPrivateKey() throws Exception {
        Assumptions.assumeTrue(SecurityUtils.isECCSupported(), "EC not supported");
        for (ECCurves c : ECCurves.VALUES) {
            if (!c.isSupported()) {
                System.out.println("Skip unsupported curve: " + c.getName());
                continue;
            }

            testLoadECPrivateKey(getClass().getSimpleName() + "-EC-" + c.getKeySize() + "-KeyPair");
        }
    }

    private KeyPair testLoadECPrivateKey(String name) throws Exception {
        return testLoadPrivateKey(name, ECPublicKey.class, ECPrivateKey.class);
    }

    private KeyPair testLoadRSAPrivateKey(String name) throws Exception {
        return testLoadPrivateKey(name, RSAPublicKey.class, RSAPrivateKey.class);
    }

    private KeyPair testLoadPrivateKey(
            String name, Class<? extends PublicKey> pubType, Class<? extends PrivateKey> prvType)
            throws Exception {
        Path folder = getTestResourcesFolder();
        Path file = folder.resolve(name);
        KeyPair kpFile = testLoadPrivateKeyFile(file, pubType, prvType);
        if (SecurityUtils.isBouncyCastleRegistered()) {
            KeyPairResourceLoader bcLoader = SecurityUtils.getBouncycastleKeyPairResourceParser();
            Collection<KeyPair> kpList = bcLoader.loadKeyPairs(null, file, TEST_PASSWORD_PROVIDER);
            assertEquals(1, GenericUtils.size(kpList), name + ": Mismatched loaded BouncyCastle keys count");

            KeyPair kpBC = GenericUtils.head(kpList);
            assertTrue(KeyUtils.compareKeyPairs(kpFile, kpBC), name + ": Mismatched BouncyCastle vs. file values");
        }

        Class<?> clazz = getClass();
        Package pkg = clazz.getPackage();
        KeyPair kpResource = testLoadPrivateKeyResource(pkg.getName().replace('.', '/') + "/" + name, pubType, prvType);
        assertTrue(KeyUtils.compareKeyPairs(kpFile, kpResource), name + ": Mismatched key file vs. resource values");
        validateKeyPairSignable(name, kpResource);
        return kpResource;
    }

    private static KeyPair testLoadPrivateKeyResource(
            String name, Class<? extends PublicKey> pubType, Class<? extends PrivateKey> prvType)
            throws IOException, GeneralSecurityException {
        return testLoadPrivateKey(
                NamedResource.ofName(name), new ClassLoadableResourceKeyPairProvider(name), pubType, prvType);
    }

    private static KeyPair testLoadPrivateKeyFile(
            Path file, Class<? extends PublicKey> pubType, Class<? extends PrivateKey> prvType)
            throws IOException, GeneralSecurityException {
        return testLoadPrivateKey(new PathResource(file), new FileKeyPairProvider(file), pubType, prvType);
    }

    private static KeyPair testLoadPrivateKey(
            NamedResource resourceKey, AbstractResourceKeyPairProvider<?> provider,
            Class<? extends PublicKey> pubType, Class<? extends PrivateKey> prvType)
            throws IOException, GeneralSecurityException {
        provider.setPasswordFinder(TEST_PASSWORD_PROVIDER);

        Iterable<KeyPair> iterator = provider.loadKeys(null);
        List<KeyPair> pairs = new ArrayList<>();
        for (KeyPair kp : iterator) {
            pairs.add(kp);
        }

        assertEquals(1, pairs.size(), "Mismatched loaded pairs count for " + resourceKey);

        KeyPair kp = pairs.get(0);
        PublicKey pub = kp.getPublic();
        assertNotNull(pub, "No public key extracted");
        assertTrue(pubType.isAssignableFrom(pub.getClass()),
                "Not an " + pubType.getSimpleName() + " public key for " + resourceKey);

        PrivateKey prv = kp.getPrivate();
        assertNotNull(prv, "No private key extracted");
        assertTrue(prvType.isAssignableFrom(prv.getClass()),
                "Not an " + prvType.getSimpleName() + " private key for " + resourceKey);

        return kp;
    }

    @Test
    void setMaxDHGroupExchangeKeySizeByProperty() {
        try {
            for (int expected = SecurityUtils.MIN_DHGEX_KEY_SIZE;
                 expected <= SecurityUtils.MAX_DHGEX_KEY_SIZE;
                 expected += 1024) {
                SecurityUtils.setMaxDHGroupExchangeKeySize(0); // force detection
                try {
                    System.setProperty(SecurityUtils.MAX_DHGEX_KEY_SIZE_PROP, Integer.toString(expected));
                    assertTrue(SecurityUtils.isDHGroupExchangeSupported(), "DH group not supported for key size=" + expected);
                    assertEquals(expected, SecurityUtils.getMaxDHGroupExchangeKeySize(), "Mismatched values");
                } finally {
                    System.clearProperty(SecurityUtils.MAX_DHGEX_KEY_SIZE_PROP);
                }
            }
        } finally {
            SecurityUtils.setMinDHGroupExchangeKeySize(0); // force detection
            SecurityUtils.setMaxDHGroupExchangeKeySize(0); // force detection
        }
    }

    @Test
    void setMaxDHGroupExchangeKeySizeProgrammatically() {
        try {
            for (int expected = SecurityUtils.MIN_DHGEX_KEY_SIZE;
                 expected <= SecurityUtils.MAX_DHGEX_KEY_SIZE;
                 expected += 1024) {
                SecurityUtils.setMaxDHGroupExchangeKeySize(expected);
                assertTrue(SecurityUtils.isDHGroupExchangeSupported(), "DH group not supported for key size=" + expected);
                assertEquals(expected, SecurityUtils.getMaxDHGroupExchangeKeySize(), "Mismatched values");
            }
        } finally {
            SecurityUtils.setMinDHGroupExchangeKeySize(0); // force detection
            SecurityUtils.setMaxDHGroupExchangeKeySize(0); // force detection
        }
    }
}
