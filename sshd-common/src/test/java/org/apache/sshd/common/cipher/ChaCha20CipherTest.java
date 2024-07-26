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

import java.nio.charset.StandardCharsets;

import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ChaCha20CipherTest extends JUnitTestSupport {
    public ChaCha20CipherTest() {
        super();
    }

    @Test
    void encryptDecrypt() throws Exception {
        ChaCha20Cipher cipher = new ChaCha20Cipher();
        byte[] key = new byte[cipher.getKdfSize()];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (i & 0xff);
        }
        byte[] iv = new byte[cipher.getIVSize()];
        BufferUtils.putLong(42, iv, 0, iv.length);
        byte[] aad = new byte[4];
        byte[] plaintext = getClass().getName().getBytes(StandardCharsets.UTF_8);
        BufferUtils.putUInt(plaintext.length, aad);
        byte[] buf = new byte[plaintext.length + cipher.getAuthenticationTagSize()];
        System.arraycopy(plaintext, 0, buf, 0, plaintext.length);
        cipher.init(Cipher.Mode.Encrypt, key, iv);
        cipher.updateAAD(aad);
        cipher.update(buf, 0, plaintext.length);

        byte[] ciphertext = buf.clone();

        cipher.init(Cipher.Mode.Decrypt, key, iv);
        cipher.updateAAD(aad);
        int length = (int) BufferUtils.getUInt(aad);
        cipher.update(ciphertext, 0, length);
        assertEquals(getClass().getName(), new String(ciphertext, 0, length, StandardCharsets.UTF_8));
    }
}
