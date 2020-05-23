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

public class BaseGCMCipher extends BaseCipher {

    private Mode mode;
    private CounterGCMParameterSpec parameters;
    private SecretKey secretKey;

    public BaseGCMCipher(
                         int ivsize, int authSize, int kdfSize, String algorithm, int keySize, String transformation,
                         int blkSize) {
        super(ivsize, authSize, kdfSize, algorithm, keySize, transformation, blkSize);
    }

    @Override
    protected byte[] initializeIVData(Mode mode, byte[] iv, int reqLen) {
        parameters
                = new CounterGCMParameterSpec(getAuthenticationTagSize() * Byte.SIZE, super.initializeIVData(mode, iv, reqLen));
        parameters.update(-1);
        return parameters.getIV();
    }

    @Override
    protected byte[] initializeKeyData(Mode mode, byte[] key, int reqLen) {
        byte[] keyData = super.initializeKeyData(mode, key, reqLen);
        secretKey = new SecretKeySpec(keyData, getAlgorithm());
        return keyData;
    }

    @Override
    protected Cipher createCipherInstance(Mode mode, byte[] key, byte[] iv) throws Exception {
        this.mode = mode;
        Cipher cipher = super.createCipherInstance(mode, key, iv);
        cipher.init(mode == Mode.Encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey, parameters);
        return cipher;
    }

    @Override
    public void updateWithAAD(byte[] input, int aadOffset, int aadLen, int inputOffset, int inputLen) throws Exception {
        Cipher cipher = getCipherInstance();
        parameters.update(1);
        cipher.init(mode == Mode.Encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey, parameters);
        cipher.updateAAD(input, aadOffset, aadLen);
        cipher.doFinal(input, inputOffset, inputLen, input, inputOffset);
    }

    public static void encodeLong(long val, byte[] buf, int off) {
        int dataLen = buf.length - off;
        if (dataLen < Long.BYTES) {
            throw new IndexOutOfBoundsException(
                    "Available data length (" + dataLen + ") cannot accommodate 64-bit integer encoding");
        }
        buf[off] = (byte) (val >> 56);
        buf[off + 1] = (byte) (val >> 48);
        buf[off + 2] = (byte) (val >> 40);
        buf[off + 3] = (byte) (val >> 32);
        buf[off + 4] = (byte) (val >> 24);
        buf[off + 5] = (byte) (val >> 16);
        buf[off + 6] = (byte) (val >> 8);
        buf[off + 7] = (byte) val;
    }

    public static long decodeLong(byte[] buf, int off, int len) {
        if (len < Long.BYTES) {
            throw new IndexOutOfBoundsException(
                    "Available data length (" + len + ") cannot accommodate 64-bit integer encoding");
        }
        long l = ((long) buf[off] << 56) & 0xff00000000000000L;
        l |= ((long) buf[off + 1] << 48) & 0x00ff000000000000L;
        l |= ((long) buf[off + 2] << 40) & 0x0000ff0000000000L;
        l |= ((long) buf[off + 3] << 32) & 0x000000ff00000000L;
        l |= ((long) buf[off + 4] << 24) & 0x00000000ff000000L;
        l |= ((long) buf[off + 5] << 16) & 0x0000000000ff0000L;
        l |= ((long) buf[off + 6] << 8) & 0x000000000000ff00L;
        l |= (buf[off + 7]) & 0x00000000000000ffL;
        return l;
    }

    /**
     * Algorithm parameters for AES/GCM that assumes the IV uses an 8-byte counter field as its most significant bytes.
     */
    protected static class CounterGCMParameterSpec extends GCMParameterSpec {
        private final byte[] iv;

        protected CounterGCMParameterSpec(int tLen, byte[] src) {
            super(tLen, src);
            iv = src.clone();
        }

        protected void update(int delta) {
            long counter = decodeLong(iv, Integer.BYTES, Long.BYTES);
            counter = (counter + delta) & 0x0ffffffffL;
            encodeLong(counter, iv, Integer.BYTES);
        }

        @Override
        public byte[] getIV() {
            return iv;
        }
    }

}
