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

package org.apache.sshd.putty;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;

import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PrivateKeyEntryDecoder;
import org.apache.sshd.common.config.keys.loader.openssh.OpenSSHKeyPairResourceParser;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnitTestSupport;

import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
abstract class AbstractPuttyTestSupport extends JUnitTestSupport {

    protected AbstractPuttyTestSupport() {
        super();
    }

    protected KeyPair testDecodeEncryptedPuttyKeyFile(
            String encryptedFile, boolean okIfMissing, String password, String keyType)
            throws IOException, GeneralSecurityException {
        PuttyKeyPairResourceParser<?, ?> parser = PuttyKeyUtils.BY_KEY_TYPE.get(keyType);
        assertNotNull(parser, "No parser found for key type=" + keyType);
        return testDecodeEncryptedPuttyKeyFile(encryptedFile, okIfMissing, password, parser, keyType);
    }

    protected KeyPair testDecodeEncryptedPuttyKeyFile(
            String encryptedFile, boolean okIfMissing, String password, PuttyKeyPairResourceParser<?, ?> parser, String keyType)
            throws IOException, GeneralSecurityException {
        assumeTrue(BuiltinCiphers.aes256cbc.isSupported(), BuiltinCiphers.aes256cbc.getTransformation() + " N/A");

        URL url = getClass().getResource(encryptedFile);
        if (url == null) {
            assumeFalse(okIfMissing, "Skip non-existent encrypted file: " + encryptedFile);
            fail("Missing test resource: " + encryptedFile);
        }

        Collection<KeyPair> keys = parser.loadKeyPairs(null, url, (s, r, index) -> password);
        assertEquals(1, GenericUtils.size(keys), "Mismatched loaded keys count from " + encryptedFile);

        return assertLoadedKeyPair(encryptedFile, GenericUtils.head(keys), keyType);
    }

    ////////////////////////////////////////////////////////////////////////////////////

    static KeyPair assertLoadedKeyPair(String prefix, KeyPair kp, String keyType) throws GeneralSecurityException {
        assertNotNull(kp, prefix + ": no key pair loaded");

        PublicKey pubKey = kp.getPublic();
        assertNotNull(pubKey, prefix + ": no public key loaded");
        assertEquals(keyType, KeyUtils.getKeyType(pubKey), prefix + ": mismatched public key type");

        PrivateKey prvKey = kp.getPrivate();
        assertNotNull(prvKey, prefix + ": no private key loaded");
        assertEquals(keyType, KeyUtils.getKeyType(prvKey), prefix + ": mismatched private key type");

        @SuppressWarnings("rawtypes")
        PrivateKeyEntryDecoder decoder = OpenSSHKeyPairResourceParser.getPrivateKeyEntryDecoder(prvKey);
        assertNotNull(decoder, "No private key decoder");

        if (decoder.isPublicKeyRecoverySupported()) {
            @SuppressWarnings("unchecked")
            PublicKey recKey = decoder.recoverPublicKey(prvKey);
            assertKeyEquals("Mismatched recovered public key", pubKey, recKey);
        }

        return kp;
    }
}
