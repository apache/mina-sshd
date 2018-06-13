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

package org.apache.sshd.common.config.keys.loader.putty;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;

import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PrivateKeyEntryDecoder;
import org.apache.sshd.common.config.keys.loader.openssh.OpenSSHKeyPairResourceParser;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Assume;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class)   // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class PuttyKeyUtilsTest extends BaseTestSupport {
    public static final String PASSWORD = "super secret passphrase";

    private final String keyType;
    private final String regularFile;
    private final String encryptedFile;
    private final PuttyKeyPairResourceParser<?, ?> parser;

    public PuttyKeyUtilsTest(String keyType) {
        this.keyType = keyType;
        this.parser = PuttyKeyUtils.BY_KEY_TYPE.get(keyType);
        this.regularFile = getClass().getSimpleName()
                + "-" + keyType + "-" + KeyPair.class.getSimpleName()
                + PuttyKeyPairResourceParser.PPK_FILE_SUFFIX;
        this.encryptedFile = PASSWORD.replace(' ', '-') + "-AES-256-CBC"
                + "-" + keyType + "-" + KeyPair.class.getSimpleName()
                + PuttyKeyPairResourceParser.PPK_FILE_SUFFIX;
    }

    @Parameters(name = "{0}")
    public static List<Object[]> parameters() {
        return parameterize(PuttyKeyUtils.BY_KEY_TYPE.keySet());
    }

    @Test
    public void testCanDecodePuttyKeyFile() throws IOException, GeneralSecurityException {
        for (String resource : new String[]{regularFile, encryptedFile}) {
            URL url = getClass().getResource(resource);
            if (GenericUtils.isSameReference(regularFile, resource)) {
                assertNotNull("Missing test resource: " + resource, url);
            } else {
                if (url == null) {
                    outputDebugMessage("Skip non-existing encrypted file: %s", resource);
                    continue;
                }
            }

            List<String> lines = IoUtils.readAllLines(url);
            assertTrue(resource + " - can extract key pair", parser.canExtractKeyPairs(resource, lines));

            for (PuttyKeyPairResourceParser<?, ?> other : PuttyKeyUtils.BY_KEY_TYPE.values()) {
                if (parser == other) {
                    continue;
                }

                assertFalse(other.getClass().getSimpleName() + "/" + resource + " - unexpected extraction capability",
                        other.canExtractKeyPairs(resource, lines));
            }
        }
    }

    @Test
    public void testDecodePuttyKeyFile() throws IOException, GeneralSecurityException {
        URL url = getClass().getResource(regularFile);
        assertNotNull("Missing test resource: " + regularFile, url);

        Collection<KeyPair> keys = parser.loadKeyPairs(url, null);
        assertEquals("Mismatched loaded keys count from " + regularFile, 1, GenericUtils.size(keys));
        assertLoadedKeyPair(regularFile, keys.iterator().next());
    }

    @Test
    public void testDecodeEncryptedPuttyKeyFile() throws IOException, GeneralSecurityException {
        Assume.assumeTrue(BuiltinCiphers.aes256cbc.getTransformation() + " N/A", BuiltinCiphers.aes256cbc.isSupported());
        URL url = getClass().getResource(encryptedFile);
        Assume.assumeTrue("Skip non-existent encrypted file: " + encryptedFile, url != null);
        assertNotNull("Missing test resource: " + encryptedFile, url);

        Collection<KeyPair> keys = parser.loadKeyPairs(url, r -> PASSWORD);
        assertEquals("Mismatched loaded keys count from " + encryptedFile, 1, GenericUtils.size(keys));

        assertLoadedKeyPair(encryptedFile, keys.iterator().next());
    }

    private void assertLoadedKeyPair(String prefix, KeyPair kp) throws GeneralSecurityException {
        assertNotNull(prefix + ": no key pair loaded", kp);

        PublicKey pubKey = kp.getPublic();
        assertNotNull(prefix + ": no public key loaded", pubKey);
        assertEquals(prefix + ": mismatched public key type", keyType, KeyUtils.getKeyType(pubKey));

        PrivateKey prvKey = kp.getPrivate();
        assertNotNull(prefix + ": no private key loaded", prvKey);
        assertEquals(prefix + ": mismatched private key type", keyType, KeyUtils.getKeyType(prvKey));

        @SuppressWarnings("rawtypes")
        PrivateKeyEntryDecoder decoder =
            OpenSSHKeyPairResourceParser.getPrivateKeyEntryDecoder(prvKey);
        assertNotNull("No private key decoder", decoder);

        if (decoder.isPublicKeyRecoverySupported()) {
            @SuppressWarnings("unchecked")
            PublicKey recKey = decoder.recoverPublicKey(prvKey);
            assertKeyEquals("Mismatched recovered public key", pubKey, recKey);
        }
    }
}
