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

package org.apache.sshd.common.mac;

import java.nio.BufferOverflowException;
import java.security.InvalidKeyException;
import java.util.Arrays;

import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;

/**
 * Poly1305 one-time message authentication code. This implementation is derived from the public domain C library
 * <a href="https://github.com/floodyberry/poly1305-donna">poly1305-donna</a>.
 *
 * @see <a href="http://cr.yp.to/mac/poly1305-20050329.pdf">The Poly1305-AES message-authentication code</a>
 */
public class Poly1305Mac implements Mac {
    public static final int KEY_BYTES = 32;
    private static final int BLOCK_SIZE = 16;

    private int r0;
    private int r1;
    private int r2;
    private int r3;
    private int r4;
    private int s1;
    private int s2;
    private int s3;
    private int s4;
    private int k0;
    private int k1;
    private int k2;
    private int k3;

    private int h0;
    private int h1;
    private int h2;
    private int h3;
    private int h4;
    private final byte[] currentBlock = new byte[BLOCK_SIZE];
    private int currentBlockOffset;

    public Poly1305Mac() {
        // empty
    }

    @Override
    public String getAlgorithm() {
        return "Poly1305";
    }

    @Override
    public void init(byte[] key) throws Exception {
        if (NumberUtils.length(key) != KEY_BYTES) {
            throw new InvalidKeyException("Poly1305 key must be 32 bytes");
        }

        int t0 = unpackIntLE(key, 0);
        int t1 = unpackIntLE(key, 4);
        int t2 = unpackIntLE(key, 8);
        int t3 = unpackIntLE(key, 12);

        // NOTE: The masks perform the key "clamping" implicitly
        r0 = t0 & 0x03FFFFFF;
        r1 = (t0 >>> 26 | t1 << 6) & 0x03FFFF03;
        r2 = (t1 >>> 20 | t2 << 12) & 0x03FFC0FF;
        r3 = (t2 >>> 14 | t3 << 18) & 0x03F03FFF;
        r4 = t3 >>> 8 & 0x000FFFFF;

        // Precompute multipliers
        s1 = r1 * 5;
        s2 = r2 * 5;
        s3 = r3 * 5;
        s4 = r4 * 5;

        k0 = unpackIntLE(key, 16);
        k1 = unpackIntLE(key, 20);
        k2 = unpackIntLE(key, 24);
        k3 = unpackIntLE(key, 28);
    }

    @Override
    public void update(byte[] in, int offset, int length) {
        while (length > 0) {
            if (currentBlockOffset == BLOCK_SIZE) {
                processBlock();
            }

            int toCopy = Math.min(length, BLOCK_SIZE - currentBlockOffset);
            System.arraycopy(in, offset, currentBlock, currentBlockOffset, toCopy);
            offset += toCopy;
            length -= toCopy;
            currentBlockOffset += toCopy;
        }
    }

    @Override
    public void updateUInt(long value) {
        byte[] encoded = new byte[Integer.BYTES];
        BufferUtils.putUInt(value, encoded);
        update(encoded);
    }

    @Override
    public void doFinal(byte[] out, int offset) throws Exception {
        if (offset + BLOCK_SIZE > NumberUtils.length(out)) {
            throw new BufferOverflowException();
        }
        if (currentBlockOffset > 0) {
            processBlock();
        }

        h1 += h0 >>> 26;
        h0 &= 0x3ffffff;
        h2 += h1 >>> 26;
        h1 &= 0x3ffffff;
        h3 += h2 >>> 26;
        h2 &= 0x3ffffff;
        h4 += h3 >>> 26;
        h3 &= 0x3ffffff;
        h0 += (h4 >>> 26) * 5;
        h4 &= 0x3ffffff;
        h1 += h0 >>> 26;
        h0 &= 0x3ffffff;

        int g0 = h0 + 5;
        int b = g0 >>> 26;
        g0 &= 0x3ffffff;
        int g1 = h1 + b;
        b = g1 >>> 26;
        g1 &= 0x3ffffff;
        int g2 = h2 + b;
        b = g2 >>> 26;
        g2 &= 0x3ffffff;
        int g3 = h3 + b;
        b = g3 >>> 26;
        g3 &= 0x3ffffff;
        int g4 = h4 + b - (1 << 26);

        b = (g4 >>> 31) - 1;
        int nb = ~b;
        h0 = h0 & nb | g0 & b;
        h1 = h1 & nb | g1 & b;
        h2 = h2 & nb | g2 & b;
        h3 = h3 & nb | g3 & b;
        h4 = h4 & nb | g4 & b;

        long f0 = Integer.toUnsignedLong(h0 | h1 << 26) + Integer.toUnsignedLong(k0);
        long f1 = Integer.toUnsignedLong(h1 >>> 6 | h2 << 20) + Integer.toUnsignedLong(k1);
        long f2 = Integer.toUnsignedLong(h2 >>> 12 | h3 << 14) + Integer.toUnsignedLong(k2);
        long f3 = Integer.toUnsignedLong(h3 >>> 18 | h4 << 8) + Integer.toUnsignedLong(k3);

        packIntLE((int) f0, out, offset);
        f1 += f0 >>> 32;
        packIntLE((int) f1, out, offset + 4);
        f2 += f1 >>> 32;
        packIntLE((int) f2, out, offset + 8);
        f3 += f2 >>> 32;
        packIntLE((int) f3, out, offset + 12);

        reset();
    }

    private void processBlock() {
        if (currentBlockOffset < BLOCK_SIZE) {
            // padding
            currentBlock[currentBlockOffset] = 1;
            for (int i = currentBlockOffset + 1; i < BLOCK_SIZE; i++) {
                currentBlock[i] = 0;
            }
        }

        long t0 = Integer.toUnsignedLong(unpackIntLE(currentBlock, 0));
        long t1 = Integer.toUnsignedLong(unpackIntLE(currentBlock, 4));
        long t2 = Integer.toUnsignedLong(unpackIntLE(currentBlock, 8));
        long t3 = Integer.toUnsignedLong(unpackIntLE(currentBlock, 12));

        h0 += t0 & 0x3ffffff;
        h1 += (t1 << 32 | t0) >>> 26 & 0x3ffffff;
        h2 += (t2 << 32 | t1) >>> 20 & 0x3ffffff;
        h3 += (t3 << 32 | t2) >>> 14 & 0x3ffffff;
        h4 += t3 >>> 8;

        if (currentBlockOffset == BLOCK_SIZE) {
            h4 += 1 << 24;
        }

        long tp0 = unsignedProduct(h0, r0) + unsignedProduct(h1, s4) + unsignedProduct(h2, s3) + unsignedProduct(h3, s2)
                   + unsignedProduct(h4, s1);
        long tp1 = unsignedProduct(h0, r1) + unsignedProduct(h1, r0) + unsignedProduct(h2, s4) + unsignedProduct(h3, s3)
                   + unsignedProduct(h4, s2);
        long tp2 = unsignedProduct(h0, r2) + unsignedProduct(h1, r1) + unsignedProduct(h2, r0) + unsignedProduct(h3, s4)
                   + unsignedProduct(h4, s3);
        long tp3 = unsignedProduct(h0, r3) + unsignedProduct(h1, r2) + unsignedProduct(h2, r1) + unsignedProduct(h3, r0)
                   + unsignedProduct(h4, s4);
        long tp4 = unsignedProduct(h0, r4) + unsignedProduct(h1, r3) + unsignedProduct(h2, r2) + unsignedProduct(h3, r1)
                   + unsignedProduct(h4, r0);

        h0 = (int) tp0 & 0x3ffffff;
        tp1 += tp0 >>> 26;
        h1 = (int) tp1 & 0x3ffffff;
        tp2 += tp1 >>> 26;
        h2 = (int) tp2 & 0x3ffffff;
        tp3 += tp2 >>> 26;
        h3 = (int) tp3 & 0x3ffffff;
        tp4 += tp3 >>> 26;
        h4 = (int) tp4 & 0x3ffffff;
        h0 += (int) (tp4 >>> 26) * 5;
        h1 += h0 >>> 26;
        h0 &= 0x3ffffff;

        currentBlockOffset = 0;
    }

    private void reset() {
        h0 = 0;
        h1 = 0;
        h2 = 0;
        h3 = 0;
        h4 = 0;
        currentBlockOffset = 0;
        Arrays.fill(currentBlock, (byte) 0);
    }

    @Override
    public int getBlockSize() {
        return BLOCK_SIZE;
    }

    @Override
    public int getDefaultBlockSize() {
        return BLOCK_SIZE;
    }

    private static int unpackIntLE(byte[] buf, int off) {
        int ret = 0;
        for (int i = 0; i < Integer.BYTES; i++) {
            ret |= Byte.toUnsignedInt(buf[off + i]) << i * Byte.SIZE;
        }
        return ret;
    }

    private static void packIntLE(int value, byte[] dst, int off) {
        for (int i = 0; i < Integer.BYTES; i++) {
            dst[off + i] = (byte) (value >>> i * Byte.SIZE);
        }
    }

    private static long unsignedProduct(int i1, int i2) {
        return Integer.toUnsignedLong(i1) * Integer.toUnsignedLong(i2);
    }
}
