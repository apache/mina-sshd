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

import javax.crypto.AEADBadTagException;

import org.apache.sshd.common.NamedFactory;

public abstract class BaseAuthenticatedCipherTest extends BaseCipherTest {

    protected BaseAuthenticatedCipherTest() {
        super();
    }

    protected void testAuthenticatedEncryptDecrypt(NamedFactory<Cipher> factory) throws Exception {
        String factoryName = factory.getName();
        Cipher enc = factory.create();
        byte[] key = new byte[enc.getKdfSize()];
        byte[] iv = new byte[enc.getIVSize()];
        enc.init(Cipher.Mode.Encrypt, key, iv);

        byte[] aad = getClass().getName().getBytes(StandardCharsets.UTF_8);
        enc.updateAAD(aad);
        String plaintext = "[Secret authenticated message using " + factoryName + ']';
        byte[] ptBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] output = new byte[ptBytes.length + enc.getAuthenticationTagSize()];
        System.arraycopy(ptBytes, 0, output, 0, ptBytes.length);
        enc.update(output, 0, ptBytes.length);

        Cipher dec = factory.create();
        dec.init(Cipher.Mode.Decrypt, key, iv);
        dec.updateAAD(aad);
        byte[] input = output.clone();
        dec.update(input, 0, ptBytes.length);
        assertEquals(getClass().getName(), new String(aad, StandardCharsets.UTF_8));
        assertEquals(plaintext, new String(input, 0, ptBytes.length, StandardCharsets.UTF_8));

        byte[] corrupted = output.clone();
        corrupted[corrupted.length - 1] += 1;
        Cipher failingDec = factory.create();
        failingDec.init(Cipher.Mode.Decrypt, key, iv);
        try {
            failingDec.updateAAD(aad.clone());
            failingDec.update(corrupted, 0, ptBytes.length);
            fail("Modified authentication tag should not validate");
        } catch (AEADBadTagException e) {
            assertNotNull(e);
        }
    }

}
