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
package org.apache.sshd.common.config.keys.loader;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Collection;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.CipherInformation;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class AESPrivateKeyObfuscatorTest extends JUnitTestSupport {
    private int keyLength;

    public void initAESPrivateKeyObfuscatorTest(int keyLength) {
        this.keyLength = keyLength;
    }

    public static List<Object[]> parameters() {
        List<Integer> lengths = AESPrivateKeyObfuscator.getAvailableKeyLengths();
        assertFalse(GenericUtils.isEmpty(lengths), "No lengths available");
        return parameterize(lengths);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "keyLength={0}")
    public void availableKeyLengthExists(int keyLength) throws GeneralSecurityException {
        initAESPrivateKeyObfuscatorTest(keyLength);
        assertEquals(0, keyLength % Byte.SIZE, "Not a BYTE size multiple");

        PrivateKeyEncryptionContext encContext = new PrivateKeyEncryptionContext();
        encContext.setCipherName(AESPrivateKeyObfuscator.CIPHER_NAME);
        encContext.setCipherMode(PrivateKeyEncryptionContext.DEFAULT_CIPHER_MODE);
        encContext.setCipherType(Integer.toString(keyLength));

        int actual = AESPrivateKeyObfuscator.INSTANCE.resolveKeyLength(encContext);
        assertEquals(keyLength, actual, "Mismatched resolved key length");

        // see SSHD-987
        byte[] iv = AESPrivateKeyObfuscator.INSTANCE.generateInitializationVector(encContext);
        assertEquals(16 /* TODO change this if GCM allowed */, iv.length, "Mismatched IV size");

        Key key = new SecretKeySpec(iv, AESPrivateKeyObfuscator.CIPHER_NAME);
        Cipher c = SecurityUtils.getCipher(AESPrivateKeyObfuscator.CIPHER_NAME);
        c.init(Cipher.DECRYPT_MODE, key);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "keyLength={0}")
    public void singleCipherMatch(int keyLength) {
        initAESPrivateKeyObfuscatorTest(keyLength);
        Predicate<CipherInformation> selector = AESPrivateKeyObfuscator.createCipherSelector(
                keyLength, PrivateKeyEncryptionContext.DEFAULT_CIPHER_MODE);
        Collection<CipherInformation> matches = BuiltinCiphers.VALUES.stream()
                .filter(selector)
                .collect(Collectors.toList());
        assertEquals(1, GenericUtils.size(matches), "Mismatched matching ciphers: " + matches);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[keyLength=" + keyLength + "]";
    }
}
