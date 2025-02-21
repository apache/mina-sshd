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
import java.util.Arrays;

import javax.crypto.AEADBadTagException;

import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.mac.Poly1305Mac;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;

/**
 * AEAD cipher based on the
 * <a href="https://github.com/openbsd/src/blob/master/usr.bin/ssh/PROTOCOL.chacha20poly1305">OpenSSH
 * ChaCha20-Poly1305</a> cipher extension.
 */
public class ChaCha20Cipher implements Cipher {
    protected final ChaChaEngine headerEngine = new ChaChaEngine();
    protected final ChaChaEngine bodyEngine = new ChaChaEngine();
    protected final Mac mac;
    protected Mode mode;

    public ChaCha20Cipher() {
        this.mac = new Poly1305Mac();
    }

    @Override
    public String getAlgorithm() {
        return "ChaCha20";
    }

    @Override
    public void init(Mode mode, byte[] key, byte[] iv) throws Exception {
        this.mode = mode;

        bodyEngine.initKey(Arrays.copyOfRange(key, 0, 32));
        bodyEngine.initNonce(iv);
        mac.init(bodyEngine.polyKey());

        headerEngine.initKey(Arrays.copyOfRange(key, 32, 64));
        headerEngine.initNonce(iv);
        headerEngine.initCounter(0);
    }

    @Override
    public void updateAAD(byte[] data, int offset, int length) throws Exception {
        ValidateUtils.checkState(mode != null, "Cipher not initialized");
        ValidateUtils.checkTrue(length == 4, "AAD only supported for encrypted packet length");

        if (mode == Mode.Decrypt) {
            mac.update(data, offset, length);
        }

        headerEngine.crypt(data, offset, length, data, offset);

        if (mode == Mode.Encrypt) {
            mac.update(data, offset, length);
        }
    }

    @Override
    public void update(byte[] input, int inputOffset, int inputLen) throws Exception {
        ValidateUtils.checkState(mode != null, "Cipher not initialized");

        if (mode == Mode.Decrypt) {
            mac.update(input, inputOffset, inputLen);
            byte[] actual = mac.doFinal();
            if (!Mac.equals(input, inputOffset + inputLen, actual, 0, actual.length)) {
                throw new AEADBadTagException("Tag mismatch");
            }
        }

        bodyEngine.crypt(input, inputOffset, inputLen, input, inputOffset);

        if (mode == Mode.Encrypt) {
            mac.update(input, inputOffset, inputLen);
            mac.doFinal(input, inputOffset + inputLen);
        }

        headerEngine.advanceNonce();
        headerEngine.initCounter(0);
        bodyEngine.advanceNonce();
        mac.init(bodyEngine.polyKey());
    }

    @Override
    public String getTransformation() {
        return "ChaCha20";
    }

    @Override
    public int getIVSize() {
        return 8;
    }

    @Override
    public int getAuthenticationTagSize() {
        return 16;
    }

    @Override
    public int getCipherBlockSize() {
        return 8;
    }

    @Override
    public int getKdfSize() {
        return 64;
    }

    @Override
    public int getKeySize() {
        return 512;
    }

    @Override
    public String toString() {
        return "chacha20-poly1305";
    }

    protected static class ChaChaEngine {
        private static final int BLOCK_BYTES = 64;
        private static final int BLOCK_INTS = BLOCK_BYTES / Integer.BYTES;
        private static final int KEY_OFFSET = 4;
        private static final int KEY_BYTES = 32;
        private static final int KEY_INTS = KEY_BYTES / Integer.BYTES;
        private static final int COUNTER_OFFSET = 12;
        private static final int NONCE_OFFSET = 14;
        private static final int[] ENGINE_STATE_HEADER = unpackSigmaString(
                "expand 32-byte k".getBytes(StandardCharsets.US_ASCII));

        protected final int[] engineState = new int[BLOCK_INTS];
        protected final byte[] keyStream = new byte[BLOCK_BYTES];
        protected final byte[] nonce = new byte[Integer.BYTES];
        protected long initialNonce;
        protected long nonceVal;

        // Elements 12 to 15 in the engineState are the counter and the nonce. The counter is a 64bit little-
        // endian value; the nonce is a 64bit big-endian value.
        //
        // The counter always starts at zero, is incremented with each full block (64 bytes), and in SSH never
        // overflows 32bits because it counts only inside a single SSH packet. The nonce in SSH is the packet
        // sequence number, which is a 32bit unsigned int that wraps around on overflow.
        //
        // Therefore, engineState[13] and engineState[14] are always zero. engineState[12] is the counter, and
        // engineState[15] is the packet sequence number in inverse byte order.

        protected ChaChaEngine() {
            System.arraycopy(ENGINE_STATE_HEADER, 0, engineState, 0, 4);
        }

        protected void initKey(byte[] key) {
            unpackIntsLE(key, 0, KEY_INTS, engineState, KEY_OFFSET);
        }

        protected void initNonce(byte[] nonce) {
            long hiBits = BufferUtils.getUInt(nonce, 0, Integer.BYTES);
            ValidateUtils.checkState(hiBits == 0, "ChaCha20 nonce is not a valid SSH packet sequence number");
            initialNonce = BufferUtils.getUInt(nonce, Integer.BYTES, Integer.BYTES);
            nonceVal = initialNonce;
            engineState[NONCE_OFFSET] = 0;
            engineState[NONCE_OFFSET + 1] = Poly1305Mac.unpackIntLE(nonce, Integer.BYTES);
        }

        protected void advanceNonce() {
            // SSH packet sequence number wraps around on uint32 overflow.
            nonceVal = (nonceVal + 1) & 0xFFFF_FFFFL;
            ValidateUtils.checkState(nonceVal != initialNonce, "Packet sequence number cannot be reused with the same key");
            BufferUtils.putUInt(nonceVal, nonce, 0, Integer.BYTES);
            engineState[NONCE_OFFSET + 1] = Poly1305Mac.unpackIntLE(nonce, 0);
        }

        protected void initCounter(long counter) {
            engineState[COUNTER_OFFSET] = (int) counter;
            engineState[COUNTER_OFFSET + 1] = 0; // Always zero; and counter never overflows in SSH.
        }

        // one-shot usage
        protected void crypt(byte[] in, int offset, int length, byte[] out, int outOffset) {
            while (length > 0) {
                setKeyStream(engineState);
                int want = Math.min(BLOCK_BYTES, length);
                for (int i = 0; i < want; i++) {
                    out[outOffset++] = (byte) (in[offset++] ^ keyStream[i]);
                }
                length -= want;
                ++engineState[COUNTER_OFFSET]; // Never overflows in SSH
            }
        }

        protected byte[] polyKey() {
            byte[] block = new byte[Poly1305Mac.KEY_BYTES];
            initCounter(0);
            crypt(block, 0, block.length, block, 0);
            initCounter(1);
            return block;
        }

        protected void setKeyStream(int[] engine) {
            int x0 = engine[0];
            int x1 = engine[1];
            int x2 = engine[2];
            int x3 = engine[3];
            int x4 = engine[4];
            int x5 = engine[5];
            int x6 = engine[6];
            int x7 = engine[7];
            int x8 = engine[8];
            int x9 = engine[9];
            int x10 = engine[10];
            int x11 = engine[11];
            int x12 = engine[12]; // counter
            int x13 = engine[13]; // 0
            int x14 = engine[14]; // 0
            int x15 = engine[15]; // nonce

            for (int i = 0; i < 10; i++) {
                // Columns
                // Quarter round 0, 4, 8, 12
                x0 += x4;
                x12 = Integer.rotateLeft(x12 ^ x0, 16);
                x8 += x12;
                x4 = Integer.rotateLeft(x4 ^ x8, 12);
                x0 += x4;
                x12 = Integer.rotateLeft(x12 ^ x0, 8);
                x8 += x12;
                x4 = Integer.rotateLeft(x4 ^ x8, 7);
                // Quarter round 1, 5, 9, 13
                x1 += x5;
                x13 = Integer.rotateLeft(x13 ^ x1, 16);
                x9 += x13;
                x5 = Integer.rotateLeft(x5 ^ x9, 12);
                x1 += x5;
                x13 = Integer.rotateLeft(x13 ^ x1, 8);
                x9 += x13;
                x5 = Integer.rotateLeft(x5 ^ x9, 7);
                // Quarter round 2, 6, 10, 14
                x2 += x6;
                x14 = Integer.rotateLeft(x14 ^ x2, 16);
                x10 += x14;
                x6 = Integer.rotateLeft(x6 ^ x10, 12);
                x2 += x6;
                x14 = Integer.rotateLeft(x14 ^ x2, 8);
                x10 += x14;
                x6 = Integer.rotateLeft(x6 ^ x10, 7);
                // Quarter round 3, 7, 11, 15
                x3 += x7;
                x15 = Integer.rotateLeft(x15 ^ x3, 16);
                x11 += x15;
                x7 = Integer.rotateLeft(x7 ^ x11, 12);
                x3 += x7;
                x15 = Integer.rotateLeft(x15 ^ x3, 8);
                x11 += x15;
                x7 = Integer.rotateLeft(x7 ^ x11, 7);
                // Diagonals
                // Quarter round 0, 5, 10, 15
                x0 += x5;
                x15 = Integer.rotateLeft(x15 ^ x0, 16);
                x10 += x15;
                x5 = Integer.rotateLeft(x5 ^ x10, 12);
                x0 += x5;
                x15 = Integer.rotateLeft(x15 ^ x0, 8);
                x10 += x15;
                x5 = Integer.rotateLeft(x5 ^ x10, 7);
                // Quarter round 1, 6, 11, 12
                x1 += x6;
                x12 = Integer.rotateLeft(x12 ^ x1, 16);
                x11 += x12;
                x6 = Integer.rotateLeft(x6 ^ x11, 12);
                x1 += x6;
                x12 = Integer.rotateLeft(x12 ^ x1, 8);
                x11 += x12;
                x6 = Integer.rotateLeft(x6 ^ x11, 7);
                // Quarter round 2, 7, 8, 13
                x2 += x7;
                x13 = Integer.rotateLeft(x13 ^ x2, 16);
                x8 += x13;
                x7 = Integer.rotateLeft(x7 ^ x8, 12);
                x2 += x7;
                x13 = Integer.rotateLeft(x13 ^ x2, 8);
                x8 += x13;
                x7 = Integer.rotateLeft(x7 ^ x8, 7);
                // Quarter round 3, 4, 9, 14
                x3 += x4;
                x14 = Integer.rotateLeft(x14 ^ x3, 16);
                x9 += x14;
                x4 = Integer.rotateLeft(x4 ^ x9, 12);
                x3 += x4;
                x14 = Integer.rotateLeft(x14 ^ x3, 8);
                x9 += x14;
                x4 = Integer.rotateLeft(x4 ^ x9, 7);
            }

            Poly1305Mac.packIntLE(engine[0] + x0, keyStream, 0);
            Poly1305Mac.packIntLE(engine[1] + x1, keyStream, 4);
            Poly1305Mac.packIntLE(engine[2] + x2, keyStream, 8);
            Poly1305Mac.packIntLE(engine[3] + x3, keyStream, 12);
            Poly1305Mac.packIntLE(engine[4] + x4, keyStream, 16);
            Poly1305Mac.packIntLE(engine[5] + x5, keyStream, 20);
            Poly1305Mac.packIntLE(engine[6] + x6, keyStream, 24);
            Poly1305Mac.packIntLE(engine[7] + x7, keyStream, 28);
            Poly1305Mac.packIntLE(engine[8] + x8, keyStream, 32);
            Poly1305Mac.packIntLE(engine[9] + x9, keyStream, 36);
            Poly1305Mac.packIntLE(engine[10] + x10, keyStream, 40);
            Poly1305Mac.packIntLE(engine[11] + x11, keyStream, 44);
            Poly1305Mac.packIntLE(engine[12] + x12, keyStream, 48);
            Poly1305Mac.packIntLE(engine[13] + x13, keyStream, 52);
            Poly1305Mac.packIntLE(engine[14] + x14, keyStream, 56);
            Poly1305Mac.packIntLE(engine[15] + x15, keyStream, 60);
        }

        private static void unpackIntsLE(byte[] buf, int off, int nrInts, int[] dst, int dstOff) {
            for (int i = 0; i < nrInts; i++) {
                dst[dstOff++] = Poly1305Mac.unpackIntLE(buf, off);
                off += Integer.BYTES;
            }
        }

        private static int[] unpackSigmaString(byte[] buf) {
            int[] values = new int[4];
            unpackIntsLE(buf, 0, 4, values, 0);
            return values;
        }

    }
}
