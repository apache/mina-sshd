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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

public class BaseCTRCipher extends BaseCipher {

    private long blocksProcessed;

    public BaseCTRCipher(int ivsize, int authSize, int kdfSize, String algorithm, int keySize, String transformation,
                         int blkSize) {
        super(ivsize, authSize, kdfSize, algorithm, keySize, transformation, blkSize);
    }

    @Override
    public void update(byte[] input, int inputOffset, int inputLen) throws Exception {
        blocksProcessed += inputLen / getCipherBlockSize();
        super.update(input, inputOffset, inputLen);
    }

    @Override
    protected void reInit(byte[] processed, int offset, int length)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        super.reInit(processed, offset, length);
        blocksProcessed = 0;
    }

    @Override
    protected AlgorithmParameterSpec determineNewParameters(byte[] processed, int offset, int length) {
        byte[] iv = getCipherInstance().getIV().clone();
        // Treat the IV as a counter and add blocksProcessed
        ByteArrayBuffer buf = new ByteArrayBuffer(iv, iv.length - Long.BYTES, Long.BYTES);
        long unsigned = buf.getLong();
        long highBitBefore = unsigned & ~Long.MAX_VALUE;
        unsigned &= Long.MAX_VALUE; // Clear most significant bit
        unsigned += blocksProcessed;
        long highBitNow = unsigned & ~Long.MAX_VALUE;
        unsigned = (unsigned & Long.MAX_VALUE) | (highBitBefore ^ highBitNow);
        int carry = (int) ((highBitBefore & highBitNow) >>> (Long.SIZE - 1));
        addCarry(iv, iv.length - Long.BYTES, carry);
        buf.wpos(iv.length - Long.BYTES);
        buf.putLong(unsigned);
        return new IvParameterSpec(iv);
    }

    private void addCarry(byte[] iv, int length, int carry) {
        int add = carry;
        for (int i = length - 1; i >= 0; i--) {
            int b = (iv[i] & 0xFF) + add;
            iv[i] = (byte) b;
            add = b >> Byte.SIZE;
        }
    }
}
