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

    private long r0;
    private long r1;
    private long r2;
    private long r3;
    private long r4;
    private long s1;
    private long s2;
    private long s3;
    private long s4;
    private long k0;
    private long k1;
    private long k2;
    private long k3;

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

        k0 = unpackIntLE(key, 16) & 0xFFFF_FFFFL;
        k1 = unpackIntLE(key, 20) & 0xFFFF_FFFFL;
        k2 = unpackIntLE(key, 24) & 0xFFFF_FFFFL;
        k3 = unpackIntLE(key, 28) & 0xFFFF_FFFFL;

        currentBlockOffset = 0;
    }

    @Override
    public void update(byte[] in, int offset, int length) {
        if (currentBlockOffset > 0) {
            // There is a partially filled block.
            int toCopy = Math.min(length, BLOCK_SIZE - currentBlockOffset);
            System.arraycopy(in, offset, currentBlock, currentBlockOffset, toCopy);
            offset += toCopy;
            length -= toCopy;
            currentBlockOffset += toCopy;
            if (currentBlockOffset == BLOCK_SIZE) {
                processBlock(currentBlock, 0, BLOCK_SIZE);
                currentBlockOffset = 0;
            }
            if (length == 0) {
                return;
            }
        }
        while (length >= BLOCK_SIZE) {
            processBlock(in, offset, BLOCK_SIZE);
            offset += BLOCK_SIZE;
            length -= BLOCK_SIZE;
        }
        if (length > 0) {
            // Put remaining bytes into internal buffer (length < BLOCK_SIZE here).
            System.arraycopy(in, offset, currentBlock, 0, length);
            currentBlockOffset = length;
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
            if (currentBlockOffset < BLOCK_SIZE) {
                // padding
                currentBlock[currentBlockOffset] = 1;
                for (int i = currentBlockOffset + 1; i < BLOCK_SIZE; i++) {
                    currentBlock[i] = 0;
                }
            }
            processBlock(currentBlock, 0, currentBlockOffset);
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

        long f0 = ((h0 | h1 << 26) & 0xFFFF_FFFFL) + k0;
        long f1 = ((h1 >>> 6 | h2 << 20) & 0xFFFF_FFFFL) + k1;
        long f2 = ((h2 >>> 12 | h3 << 14) & 0xFFFF_FFFFL) + k2;
        long f3 = ((h3 >>> 18 | h4 << 8) & 0xFFFF_FFFFL) + k3;

        packIntLE((int) f0, out, offset);
        f1 += f0 >>> 32;
        packIntLE((int) f1, out, offset + 4);
        f2 += f1 >>> 32;
        packIntLE((int) f2, out, offset + 8);
        f3 += f2 >>> 32;
        packIntLE((int) f3, out, offset + 12);

        reset();
    }

    private void processBlock(byte[] block, int offset, int length) {

        int t0 = unpackIntLE(block, offset);
        int t1 = unpackIntLE(block, offset + 4);
        int t2 = unpackIntLE(block, offset + 8);
        int t3 = unpackIntLE(block, offset + 12);

        h0 += t0 & 0x3ffffff;
        h1 += (t0 >>> 26 | t1 << 6) & 0x3ffffff;
        h2 += (t1 >>> 20 | t2 << 12) & 0x3ffffff;
        h3 += (t2 >>> 14 | t3 << 18) & 0x3ffffff;
        h4 += t3 >>> 8;

        if (length == BLOCK_SIZE) {
            h4 += 1 << 24;
        }

        // The high bits of h0 to h4 are guaranteed to be zero, so we can just let the compiler extend the ints.
        // No need to do a & 0xFFFF_FFFFL.
        long l0 = h0;
        long l1 = h1;
        long l2 = h2;
        long l3 = h3;
        long l4 = h4;
        long tp0 = l0 * r0 + l1 * s4 + l2 * s3 + l3 * s2 + l4 * s1;
        long tp1 = l0 * r1 + l1 * r0 + l2 * s4 + l3 * s3 + l4 * s2;
        long tp2 = l0 * r2 + l1 * r1 + l2 * r0 + l3 * s4 + l4 * s3;
        long tp3 = l0 * r3 + l1 * r2 + l2 * r1 + l3 * r0 + l4 * s4;
        long tp4 = l0 * r4 + l1 * r3 + l2 * r2 + l3 * r1 + l4 * r0;

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

    public static int unpackIntLE(byte[] buf, int off) {
        int ret = buf[off++] & 0xFF;
        ret |= (buf[off++] & 0xFF) << 8;
        ret |= (buf[off++] & 0xFF) << 16;
        ret |= (buf[off] & 0xFF) << 24;
        return ret;
    }

    public static void packIntLE(int value, byte[] dst, int off) {
        dst[off++] = (byte) value;
        dst[off++] = (byte) (value >> 8);
        dst[off++] = (byte) (value >> 16);
        dst[off] = (byte) (value >> 24);
    }
}
