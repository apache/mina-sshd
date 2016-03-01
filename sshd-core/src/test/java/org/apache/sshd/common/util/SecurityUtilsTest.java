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

package org.apache.sshd.common.util;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.AbstractClassLoadableResourceKeyPairProvider;
import org.apache.sshd.common.keyprovider.AbstractFileKeyPairProvider;
import org.apache.sshd.common.keyprovider.AbstractResourceKeyPairProvider;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.Assume;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SecurityUtilsTest extends BaseTestSupport {
    private static final String DEFAULT_PASSWORD = "super secret passphrase";
    private static final FilePasswordProvider TEST_PASSWORD_PROVIDER = new FilePasswordProvider() {
        @Override
        public String getPassword(String file) throws IOException {
            return DEFAULT_PASSWORD;
        }
    };

    public SecurityUtilsTest() {
        super();
    }

    @Test
    public void testLoadEncryptedDESPrivateKey() {
        Assume.assumeTrue("Bouncycastle not registered", SecurityUtils.isBouncyCastleRegistered());
        testLoadEncryptedRSAPrivateKey("DES-EDE3");
    }

    @Test
    public void testLoadEncryptedAESPrivateKey() {
        Assume.assumeTrue("Bouncycastle not registered", SecurityUtils.isBouncyCastleRegistered());
        for (BuiltinCiphers c : new BuiltinCiphers[]{
            BuiltinCiphers.aes128cbc, BuiltinCiphers.aes192cbc, BuiltinCiphers.aes256cbc
        }) {
            if (!c.isSupported()) {
                System.out.println("Skip unsupported encryption scheme: " + c.getName());
                continue;
            }

            testLoadEncryptedRSAPrivateKey("AES-" + c.getKeySize());
        }
    }

    private KeyPair testLoadEncryptedRSAPrivateKey(String algorithm) {
        return testLoadRSAPrivateKey(DEFAULT_PASSWORD.replace(' ', '-') + "-RSA-" + algorithm.toUpperCase() + "-key");
    }

    @Test
    public void testLoadUnencryptedRSAPrivateKey() {
        Assume.assumeTrue("Bouncycastle not registered", SecurityUtils.isBouncyCastleRegistered());
        testLoadRSAPrivateKey(getClass().getSimpleName() + "-RSA-KeyPair");
    }

    @Test
    public void testLoadUnencryptedDSSPrivateKey() {
        Assume.assumeTrue("Bouncycastle not registered", SecurityUtils.isBouncyCastleRegistered());
        testLoadDSSPrivateKey(getClass().getSimpleName() + "-DSA-KeyPair");
    }

    private KeyPair testLoadDSSPrivateKey(String name) {
        return testLoadPrivateKey(name, DSAPublicKey.class, DSAPrivateKey.class);
    }

    @Test
    public void testLoadUnencryptedECPrivateKey() {
        Assume.assumeTrue("Bouncycastle not registered", SecurityUtils.isBouncyCastleRegistered());
        Assume.assumeTrue("EC not supported", SecurityUtils.hasEcc());
        for (ECCurves c : ECCurves.VALUES) {
            if (!c.isSupported()) {
                System.out.println("Skip unsupported curve: " + c.getName());
                continue;
            }

            testLoadECPrivateKey(getClass().getSimpleName() + "-EC-" + c.getKeySize() + "-KeyPair");
        }
    }

    private KeyPair testLoadECPrivateKey(String name) {
        return testLoadPrivateKey(name, ECPublicKey.class, ECPrivateKey.class);
    }

    private KeyPair testLoadRSAPrivateKey(String name) {
        return testLoadPrivateKey(name, RSAPublicKey.class, RSAPrivateKey.class);
    }

    private KeyPair testLoadPrivateKey(String name, Class<? extends PublicKey> pubType, Class<? extends PrivateKey> prvType) {
        Path folder = getClassResourcesFolder(TEST_SUBFOLDER);
        KeyPair kpFile = testLoadPrivateKeyFile(folder.resolve(name), pubType, prvType);
        Class<?> clazz = getClass();
        Package pkg = clazz.getPackage();
        KeyPair kpResource = testLoadPrivateKeyResource(pkg.getName().replace('.', '/') + "/" + name, pubType, prvType);

        assertTrue("Mismatched key pairs values", KeyUtils.compareKeyPairs(kpFile, kpResource));
        return kpResource;
    }

    private static KeyPair testLoadPrivateKeyResource(String name, Class<? extends PublicKey> pubType, Class<? extends PrivateKey> prvType) {
        AbstractClassLoadableResourceKeyPairProvider provider = SecurityUtils.createClassLoadableResourceKeyPairProvider();
        provider.setResources(Collections.singletonList(name));
        return testLoadPrivateKey(name, provider, pubType, prvType);
    }

    private static KeyPair testLoadPrivateKeyFile(Path file, Class<? extends PublicKey> pubType, Class<? extends PrivateKey> prvType) {
        AbstractFileKeyPairProvider provider = SecurityUtils.createFileKeyPairProvider();
        provider.setPaths(Collections.singletonList(file));
        return testLoadPrivateKey(file.toString(), provider, pubType, prvType);
    }

    private static KeyPair testLoadPrivateKey(String resourceKey, AbstractResourceKeyPairProvider<?> provider,
            Class<? extends PublicKey> pubType, Class<? extends PrivateKey> prvType) {
        provider.setPasswordFinder(TEST_PASSWORD_PROVIDER);
        Iterable<KeyPair> iterator = provider.loadKeys();
        List<KeyPair> pairs = new ArrayList<KeyPair>();
        for (KeyPair kp : iterator) {
            pairs.add(kp);
        }

        assertEquals("Mismatched loaded pairs count for " + resourceKey, 1, pairs.size());

        KeyPair kp = pairs.get(0);
        PublicKey pub = kp.getPublic();
        assertNotNull("No public key extracted", pub);
        assertTrue("Not an " + pubType.getSimpleName() + " public key for " + resourceKey, pubType.isAssignableFrom(pub.getClass()));

        PrivateKey prv = kp.getPrivate();
        assertNotNull("No private key extracted", prv);
        assertTrue("Not an " + prvType.getSimpleName() + " private key for " + resourceKey, prvType.isAssignableFrom(prv.getClass()));

        return kp;
    }

    @Test
    public void testBouncyCastleRegistrationSettings() {
        Assume.assumeTrue("Bouncycastle not registered", SecurityUtils.isBouncyCastleRegistered());
        assertTrue("DH Group Exchange not supported", SecurityUtils.isDHGroupExchangeSupported());
        assertEquals("Mismatched max. DH group exchange key size", SecurityUtils.MAX_DHGEX_KEY_SIZE, SecurityUtils.getMaxDHGroupExchangeKeySize());
        assertTrue("ECC not supported", SecurityUtils.hasEcc());
    }

    @Test
    public void testBouncyCastleRegistrationProperty() throws GeneralSecurityException {
        String propValue = System.getProperty(SecurityUtils.REGISTER_BOUNCY_CASTLE_PROP);
        Assume.assumeFalse(SecurityUtils.REGISTER_BOUNCY_CASTLE_PROP + " property not set", GenericUtils.isEmpty(propValue));
        Assume.assumeFalse(SecurityUtils.REGISTER_BOUNCY_CASTLE_PROP + " property is " + propValue, Boolean.parseBoolean(propValue));
        assertFalse("Unexpected registration of provider", SecurityUtils.isBouncyCastleRegistered());

        KeyPairGenerator kpg = SecurityUtils.getKeyPairGenerator(KeyUtils.RSA_ALGORITHM);
        Provider provider = kpg.getProvider();
        assertNotEquals("Unexpected used provider", SecurityUtils.BOUNCY_CASTLE, provider.getName());
    }

    @Test
    public void testSetMaxDHGroupExchangeKeySizeByProperty() {
        try {
            for (int expected = SecurityUtils.MIN_DHGEX_KEY_SIZE; expected <= SecurityUtils.MAX_DHGEX_KEY_SIZE; expected += 1024) {
                SecurityUtils.setMaxDHGroupExchangeKeySize(0);  // force detection
                try {
                    System.setProperty(SecurityUtils.MAX_DHGEX_KEY_SIZE_PROP, Integer.toString(expected));
                    assertTrue("DH group not supported for key size=" + expected, SecurityUtils.isDHGroupExchangeSupported());
                    assertEquals("Mismatched values", expected, SecurityUtils.getMaxDHGroupExchangeKeySize());
                } finally {
                    System.clearProperty(SecurityUtils.MAX_DHGEX_KEY_SIZE_PROP);
                }
            }
        } finally {
            SecurityUtils.setMaxDHGroupExchangeKeySize(0);  // force detection
        }
    }

    @Test
    public void testSetMaxDHGroupExchangeKeySizeProgrammatically() {
        try {
            for (int expected = SecurityUtils.MIN_DHGEX_KEY_SIZE; expected <= SecurityUtils.MAX_DHGEX_KEY_SIZE; expected += 1024) {
                SecurityUtils.setMaxDHGroupExchangeKeySize(expected);
                assertTrue("DH group not supported for key size=" + expected, SecurityUtils.isDHGroupExchangeSupported());
                assertEquals("Mismatched values", expected, SecurityUtils.getMaxDHGroupExchangeKeySize());
            }
        } finally {
            SecurityUtils.setMaxDHGroupExchangeKeySize(0);  // force detection
        }
    }
}
