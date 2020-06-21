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

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

public class BaseGCMCipher extends BaseCipher {

    protected Mode mode;
    protected CounterGCMParameterSpec parameters;
    protected SecretKey secretKey;

    public BaseGCMCipher(
                         int ivsize, int authSize, int kdfSize, String algorithm, int keySize, String transformation,
                         int blkSize) {
        super(ivsize, authSize, kdfSize, algorithm, keySize, transformation, blkSize);
    }

    @Override
    protected Cipher createCipherInstance(Mode mode, byte[] key, byte[] iv) throws Exception {
        this.mode = mode;
        secretKey = new SecretKeySpec(key, getAlgorithm());
        parameters = new CounterGCMParameterSpec(getAuthenticationTagSize() * Byte.SIZE, iv);
        return SecurityUtils.getCipher(getTransformation());
    }

    @Override
    public void update(byte[] input, int inputOffset, int inputLen) throws Exception {
        updateWithAAD(input, inputOffset, 0, inputLen);
    }

    @Override
    public void updateWithAAD(byte[] input, int offset, int aadLen, int inputLen) throws Exception {
        Cipher cipher = getCipherInstance();
        cipher.init(mode == Mode.Encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey, parameters);
        if (aadLen > 0) {
            cipher.updateAAD(input, offset, aadLen);
        }
        int inputOffset = offset + aadLen;
        if (mode == Mode.Decrypt) {
            inputLen += getAuthenticationTagSize();
        }
        cipher.doFinal(input, inputOffset, inputLen, input, inputOffset);
        parameters.incrementCounter();
    }

    /**
     * Algorithm parameters for AES/GCM that assumes the IV uses an 8-byte counter field as its most significant bytes.
     */
    protected static class CounterGCMParameterSpec extends GCMParameterSpec {
        protected final byte[] iv;

        protected CounterGCMParameterSpec(int tLen, byte[] src) {
            super(tLen, src);
            if (src.length != 12) {
                throw new IllegalArgumentException("GCM nonce must be 12 bytes, but given len=" + src.length);
            }
            iv = src.clone();
        }

        protected void incrementCounter() {
            int off = iv.length - Long.BYTES;
            long counter = BufferUtils.getLong(iv, off, Long.BYTES);
            BufferUtils.putLong(Math.addExact(counter, 1L), iv, off, Long.BYTES);
        }

        @Override
        public byte[] getIV() {
            // JCE implementation of GCM will complain if the reference doesn't change between inits
            return iv.clone();
        }
    }

}
