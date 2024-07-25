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
package org.apache.sshd.common.cipher;

import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.sshd.common.cipher.Cipher.Mode;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Tag("NoIoTestCase")
public class BaseCipherResetTest extends JUnitTestSupport {

    private static final Random RND = new SecureRandom();

    private String providerName;

    private BuiltinCiphers builtIn;

    public void initBaseCipherResetTest(String providerName, BuiltinCiphers builtIn, String name) {
        this.providerName = providerName;
        this.builtIn = builtIn;
        if ("BC".equals(providerName)) {
            registerBouncyCastleProviderIfNecessary();
        }
    }

    private static void registerBouncyCastleProviderIfNecessary() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static List<Object[]> getParameters() {
        List<Object[]> items = new ArrayList<>();
        for (BuiltinCiphers c : BuiltinCiphers.values()) {
            String name = c.getName();
            if (name.endsWith("-cbc") || name.endsWith("-ctr")) {
                items.add(new Object[] { "SunJCE", c, c.getName() });
                items.add(new Object[] { "BC", c, c.getName() });
            }
        }
        return items;
    }

    @BeforeEach
    void changeCipher() {
        BaseCipher.factory = t -> javax.crypto.Cipher.getInstance(t, providerName);
        BaseCipher.alwaysReInit = true;
    }

    @AfterEach
    void resetCipher() {
        BaseCipher.factory = SecurityUtils::getCipher;
        BaseCipher.alwaysReInit = false;
    }

    private void checkBuffer(byte[] data, int index, byte[] front, byte[] back) {
        byte[] expected = front.clone();
        System.arraycopy(back, index, expected, index, back.length - index);
        assertArrayEquals(expected, data, "Mismatched bytes at " + index);
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "{2} - {0}")
    public void reset(String providerName, BuiltinCiphers builtIn, String name) throws Exception {
        initBaseCipherResetTest(providerName, builtIn, name);
        byte[] plaintext = new byte[builtIn.getCipherBlockSize() * 30];
        for (int i = 0; i < plaintext.length; i++) {
            plaintext[i] = (byte) (' ' + i);
        }
        byte[] key = new byte[builtIn.getKdfSize()];
        RND.nextBytes(key);
        byte[] iv = new byte[builtIn.getIVSize()];
        RND.nextBytes(iv);
        // Set last 8 bytes of iv to 0xff so we can see that the overflow is handled correctly
        for (int i = iv.length - 8; i < iv.length; i++) {
            iv[i] = (byte) 0xff;
        }
        iv[iv.length - 1] = (byte) 0xf5;
        // Now the upper 8 bytes correspond to -11. We process 30 blocks, so in CTR mode we should see that overflow is
        // handled correctly.
        SecretKey secretKey = new SecretKeySpec(key, builtIn.getAlgorithm());
        AlgorithmParameterSpec param = new IvParameterSpec(iv);
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(builtIn.getTransformation(), providerName);
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey, param);
        byte[] encrypted = cipher.doFinal(plaintext);
        assertEquals(plaintext.length, encrypted.length, "Mismatched length");
        Cipher sshCipher = builtIn.create();
        sshCipher.init(Mode.Encrypt, key, iv);
        byte[] sshText = plaintext.clone();
        // Encrypt it all
        sshCipher.update(sshText);
        assertArrayEquals(encrypted, sshText, "Mismatched encrypted bytes");
        // Same, but encrypt block by block
        sshCipher = builtIn.create();
        sshCipher.init(Mode.Encrypt, key, iv);
        sshText = plaintext.clone();
        int blockSize = builtIn.getCipherBlockSize();
        for (int i = 0; i < sshText.length; i += blockSize) {
            sshCipher.update(sshText, i, blockSize);
            checkBuffer(sshText, i + blockSize, encrypted, plaintext);
        }
        assertArrayEquals(encrypted, sshText, "Mismatched encrypted bytes");
        // Same, but encrypt six times five blocks
        sshCipher = builtIn.create();
        sshCipher.init(Mode.Encrypt, key, iv);
        sshText = plaintext.clone();
        blockSize = builtIn.getCipherBlockSize() * 5;
        for (int i = 0; i < sshText.length; i += blockSize) {
            sshCipher.update(sshText, i, blockSize);
            checkBuffer(sshText, i + blockSize, encrypted, plaintext);
        }
        assertArrayEquals(encrypted, sshText, "Mismatched encrypted bytes");
        // Decrypt in all three ways: should be equal to the original plaintext
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey, param);
        byte[] decrypted = cipher.doFinal(encrypted);
        assertArrayEquals(plaintext, decrypted, "Mismatched encrypted bytes");
        sshCipher = builtIn.create();
        sshCipher.init(Mode.Decrypt, key, iv);
        byte[] data = encrypted.clone();
        sshCipher.update(data);
        assertArrayEquals(plaintext, data, "Mismatched encrypted bytes");
        sshCipher = builtIn.create();
        sshCipher.init(Mode.Decrypt, key, iv);
        data = encrypted.clone();
        blockSize = builtIn.getCipherBlockSize();
        for (int i = 0; i < data.length; i += blockSize) {
            sshCipher.update(data, i, blockSize);
            checkBuffer(data, i + blockSize, plaintext, encrypted);
        }
        assertArrayEquals(plaintext, data, "Mismatched encrypted bytes");
        sshCipher = builtIn.create();
        sshCipher.init(Mode.Decrypt, key, iv);
        data = encrypted.clone();
        blockSize = builtIn.getCipherBlockSize() * 5;
        for (int i = 0; i < data.length; i += blockSize) {
            sshCipher.update(data, i, blockSize);
            checkBuffer(data, i + blockSize, plaintext, encrypted);
        }
        assertArrayEquals(plaintext, data, "Mismatched encrypted bytes");
    }
}
