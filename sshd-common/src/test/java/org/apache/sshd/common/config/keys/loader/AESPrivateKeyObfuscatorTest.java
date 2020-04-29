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
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
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
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class AESPrivateKeyObfuscatorTest extends JUnitTestSupport {
    private final int keyLength;

    public AESPrivateKeyObfuscatorTest(int keyLength) {
        this.keyLength = keyLength;
    }

    @Parameters(name = "keyLength={0}")
    public static List<Object[]> parameters() {
        List<Integer> lengths = AESPrivateKeyObfuscator.getAvailableKeyLengths();
        assertFalse("No lengths available", GenericUtils.isEmpty(lengths));
        return parameterize(lengths);
    }

    @Test
    public void testAvailableKeyLengthExists() throws GeneralSecurityException {
        assertEquals("Not a BYTE size multiple", 0, keyLength % Byte.SIZE);

        PrivateKeyEncryptionContext encContext = new PrivateKeyEncryptionContext();
        encContext.setCipherName(AESPrivateKeyObfuscator.CIPHER_NAME);
        encContext.setCipherMode(PrivateKeyEncryptionContext.DEFAULT_CIPHER_MODE);
        encContext.setCipherType(Integer.toString(keyLength));

        int actual = AESPrivateKeyObfuscator.INSTANCE.resolveKeyLength(encContext);
        assertEquals("Mismatched resolved key length", keyLength, actual);

        // see SSHD-987
        byte[] iv = AESPrivateKeyObfuscator.INSTANCE.generateInitializationVector(encContext);
        assertEquals("Mismatched IV size", 16 /* TODO change this if GCM allowed */, iv.length);

        Key key = new SecretKeySpec(iv, AESPrivateKeyObfuscator.CIPHER_NAME);
        Cipher c = SecurityUtils.getCipher(AESPrivateKeyObfuscator.CIPHER_NAME);
        c.init(Cipher.DECRYPT_MODE, key);
    }

    @Test
    public void testSingleCipherMatch() {
        Predicate<CipherInformation> selector = AESPrivateKeyObfuscator.createCipherSelector(
                keyLength, PrivateKeyEncryptionContext.DEFAULT_CIPHER_MODE);
        Collection<CipherInformation> matches = BuiltinCiphers.VALUES.stream()
                .filter(selector)
                .collect(Collectors.toList());
        assertEquals("Mismatched matching ciphers: " + matches, 1, GenericUtils.size(matches));
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[keyLength=" + keyLength + "]";
    }
}
