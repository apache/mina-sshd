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
import org.apache.sshd.common.util.NumberUtils;
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
    protected final Mac mac = new Poly1305Mac();
    protected Mode mode;

    public ChaCha20Cipher() {
        // empty
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
        return 256;
    }

    protected static class ChaChaEngine {
        private static final int BLOCK_BYTES = 64;
        private static final int BLOCK_INTS = BLOCK_BYTES / Integer.BYTES;
        private static final int KEY_OFFSET = 4;
        private static final int KEY_BYTES = 32;
        private static final int KEY_INTS = KEY_BYTES / Integer.BYTES;
        private static final int COUNTER_OFFSET = 12;
        private static final int NONCE_OFFSET = 14;
        private static final int NONCE_BYTES = 8;
        private static final int NONCE_INTS = NONCE_BYTES / Integer.BYTES;
        private static final int[] ENGINE_STATE_HEADER
                = unpackSigmaString("expand 32-byte k".getBytes(StandardCharsets.US_ASCII));

        protected final int[] x = new int[BLOCK_INTS];
        protected final int[] engineState = new int[BLOCK_INTS];
        protected final byte[] nonce = new byte[NONCE_BYTES];
        protected long initialNonce;

        protected ChaChaEngine() {
            System.arraycopy(ENGINE_STATE_HEADER, 0, engineState, 0, 4);
        }

        protected void initKey(byte[] key) {
            unpackIntsLE(key, 0, KEY_INTS, engineState, KEY_OFFSET);
        }

        protected void initNonce(byte[] nonce) {
            initialNonce = BufferUtils.getLong(nonce, 0, NumberUtils.length(nonce));
            unpackIntsLE(nonce, 0, NONCE_INTS, engineState, NONCE_OFFSET);
            System.arraycopy(nonce, 0, this.nonce, 0, NONCE_BYTES);
        }

        protected void advanceNonce() {
            long counter = BufferUtils.getLong(nonce, 0, NONCE_BYTES) + 1;
            ValidateUtils.checkState(counter != initialNonce, "Packet sequence number cannot be reused with the same key");
            BufferUtils.putLong(counter, nonce, 0, NONCE_BYTES);
            unpackIntsLE(nonce, 0, NONCE_INTS, engineState, NONCE_OFFSET);
        }

        protected void initCounter(long counter) {
            engineState[COUNTER_OFFSET] = (int) counter;
            engineState[COUNTER_OFFSET + 1] = (int) (counter >>> Integer.SIZE);
        }

        // one-shot usage
        protected void crypt(byte[] in, int offset, int length, byte[] out, int outOffset) {
            while (length > 0) {
                System.arraycopy(engineState, 0, x, 0, BLOCK_INTS);
                permute(x);
                int want = Math.min(BLOCK_BYTES, length);
                for (int i = 0, j = 0; i < want; i += Integer.BYTES, j++) {
                    int keyStream = engineState[j] + x[j];
                    int take = Math.min(Integer.BYTES, length);
                    int input = unpackIntLE(in, offset, take);
                    int output = keyStream ^ input;
                    packIntLE(output, out, outOffset, take);
                    offset += take;
                    outOffset += take;
                    length -= take;
                }
                int lo = ++engineState[COUNTER_OFFSET];
                if (lo == 0) {
                    // overflow
                    ++engineState[COUNTER_OFFSET + 1];
                }
            }
        }

        protected byte[] polyKey() {
            byte[] block = new byte[Poly1305Mac.KEY_BYTES];
            initCounter(0);
            crypt(block, 0, block.length, block, 0);
            initCounter(1);
            return block;
        }

        protected static void permute(int[] state) {
            for (int i = 0; i < 10; i++) {
                columnRound(state);
                diagonalRound(state);
            }
        }

        protected static void columnRound(int[] state) {
            quarterRound(state, 0, 4, 8, 12);
            quarterRound(state, 1, 5, 9, 13);
            quarterRound(state, 2, 6, 10, 14);
            quarterRound(state, 3, 7, 11, 15);
        }

        protected static void diagonalRound(int[] state) {
            quarterRound(state, 0, 5, 10, 15);
            quarterRound(state, 1, 6, 11, 12);
            quarterRound(state, 2, 7, 8, 13);
            quarterRound(state, 3, 4, 9, 14);
        }

        protected static void quarterRound(int[] state, int a, int b, int c, int d) {
            state[a] += state[b];
            state[d] = Integer.rotateLeft(state[d] ^ state[a], 16);

            state[c] += state[d];
            state[b] = Integer.rotateLeft(state[b] ^ state[c], 12);

            state[a] += state[b];
            state[d] = Integer.rotateLeft(state[d] ^ state[a], 8);

            state[c] += state[d];
            state[b] = Integer.rotateLeft(state[b] ^ state[c], 7);
        }

        private static int unpackIntLE(byte[] buf, int off) {
            return unpackIntLE(buf, off, Integer.BYTES);
        }

        private static int unpackIntLE(byte[] buf, int off, int len) {
            int ret = 0;
            for (int i = 0; i < len; i++) {
                ret |= Byte.toUnsignedInt(buf[off + i]) << i * Byte.SIZE;
            }
            return ret;
        }

        private static void unpackIntsLE(byte[] buf, int off, int nrInts, int[] dst, int dstOff) {
            for (int i = 0; i < nrInts; i++) {
                dst[dstOff++] = unpackIntLE(buf, off);
                off += Integer.BYTES;
            }
        }

        private static int[] unpackSigmaString(byte[] buf) {
            int[] values = new int[4];
            unpackIntsLE(buf, 0, 4, values, 0);
            return values;
        }

        private static void packIntLE(int value, byte[] dst, int off, int len) {
            for (int i = 0; i < len; i++) {
                dst[off + i] = (byte) (value >>> i * Byte.SIZE);
            }
        }
    }
}
