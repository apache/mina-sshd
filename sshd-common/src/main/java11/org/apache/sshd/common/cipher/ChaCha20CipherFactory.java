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

import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import javax.crypto.AEADBadTagException;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.mac.Poly1305Mac;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class ChaCha20CipherFactory implements Supplier<Cipher> {

    public static final ChaCha20CipherFactory INSTANCE = new ChaCha20CipherFactory();

    private static final Logger LOG = LoggerFactory.getLogger(ChaCha20CipherFactory.class);

    private static final AtomicReference<Boolean> SUPPORTED = new AtomicReference<>();

    private ChaCha20CipherFactory() {
        super();
    }

    @Override
    public Cipher get() {
        if (hasChaCha20()) {
            LOG.debug("Using SunJCE ChaCha20");
            return ChaCha20Jdk.get();
        }
        // If there is no SunJCE provider, fall back to using own implementation.
        LOG.debug("Using Java11 factory, but Java 8 ChaCha20.");
        return new ChaCha20Cipher();
    }

    private boolean hasChaCha20() {
        Boolean supported = SUPPORTED.get();
        if (supported == null) {
            try {
                javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("ChaCha20", "SunJCE");
                supported = Boolean.valueOf(cipher != null);
            } catch (GeneralSecurityException e) {
                supported = Boolean.FALSE;
            }
            if (!SUPPORTED.compareAndSet(null, supported)) {
                supported = SUPPORTED.get();
            }
        }
        return supported.booleanValue();
    }

    private static class ChaCha20Jdk extends AbstractChaCha20Cipher {
        protected final javax.crypto.Cipher headerEngine;
        protected final javax.crypto.Cipher bodyEngine;
        protected final Mac mac = new Poly1305Mac();
        protected Mode mode;

        private byte[] nonce;
        private long initialNonce;
        private SecretKeySpec k1, k2;

        static Cipher get() {
            try {
                javax.crypto.Cipher header = javax.crypto.Cipher.getInstance("ChaCha20", "SunJCE");
                javax.crypto.Cipher body = javax.crypto.Cipher.getInstance("ChaCha20", "SunJCE");
                return new ChaCha20Jdk(header, body);
            } catch (GeneralSecurityException e) {
                // Should not happen; we check before we call get().
                throw new IllegalStateException(e.getMessage(), e);
            }
        }

        private ChaCha20Jdk(javax.crypto.Cipher header, javax.crypto.Cipher body) {
            this.headerEngine = header;
            this.bodyEngine = body;
        }

        @Override
        public void init(Mode mode, byte[] key, byte[] iv) throws Exception {
            this.mode = mode;

            long hiBits = BufferUtils.getUInt(iv, 0, 4);
            ValidateUtils.checkState(hiBits == 0, "ChaCha20 nonce is not a valid SSH packet sequence number");
            initialNonce = BufferUtils.getUInt(iv, 4, 8);
            // In: 64 bytes key (512bits) and 8 bytes (64bits) nonce (IV)
            // JDK requires 32 bytes for the key (256 bits), and 12 bytes (96 bits) for the nonce.
            // JDK implements ChaCha20 as specified in RFC 8439. SSH uses the original version.
            //
            // JDK uses a 32bit counter plus the 96 bit nonce where SSH uses a 64bit counter and
            // a 64bit nonce. But in SSH, the hi 32 bits of the counter are always zero. Encryption
            // happens at SSH packet level, and SSH packets have a maximum length that is way below
            // 4GB. (More like a few kB, typically 32kB.) The packet sequence number goes into the
            // nonce, and is incremented with each packet. The nonce in SSH thus always has only
            // the last 32 bits set, the other bits are zero.
            //
            // Because of this behavior of SSH, we can simply provide a 96bit nonce by concatenating
            // 32 zero bits with the given 64 IV bits, and then the RFC 8439 algorithm can be used.
            // This works because the ChaCha20 spec treat the counter as a little-endian integer,
            // while the SSH nonce is the packet sequence number in big-endian format. So the middle
            // 64 bits of the concatenation of counter and nonce are always zero, irrespective of
            // whether the 64bit values are used for both, or a 32bit counter and a 96bit nonce.
            //
            // See also https://datatracker.ietf.org/doc/html/rfc8439 .
            nonce = new byte[12];
            System.arraycopy(iv, 4, nonce, 8, 4);
            AlgorithmParameterSpec algorithmParameterSpec = new ChaCha20ParameterSpec(nonce, 0);
            k1 = new SecretKeySpec(Arrays.copyOfRange(key, 0, 32), "ChaCha20");
            bodyEngine.init(mode == Mode.Encrypt ? javax.crypto.Cipher.ENCRYPT_MODE : javax.crypto.Cipher.DECRYPT_MODE, k1, algorithmParameterSpec);
            init(mac, bodyEngine);

            k2 = new SecretKeySpec(Arrays.copyOfRange(key, 32, 64), "ChaCha20");
            headerEngine.init(mode == Mode.Encrypt ? javax.crypto.Cipher.ENCRYPT_MODE : javax.crypto.Cipher.DECRYPT_MODE, k2, algorithmParameterSpec);
        }

        @Override
        public void updateAAD(byte[] data, int offset, int length) throws Exception {
            ValidateUtils.checkState(mode != null, "Cipher not initialized");
            ValidateUtils.checkTrue(length == 4, "AAD only supported for encrypted packet length");

            if (mode == Mode.Decrypt) {
                mac.update(data, offset, length);
            }

            headerEngine.doFinal(data, offset, length, data, offset);

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

            bodyEngine.doFinal(input, inputOffset, inputLen, input, inputOffset);

            if (mode == Mode.Encrypt) {
                mac.update(input, inputOffset, inputLen);
                mac.doFinal(input, inputOffset + inputLen);
            }

            // Prepare for the next round
            // Increment the nonce (SSH sequence numbers wrap around on uint32 overflow)
            long counter = (BufferUtils.getUInt(nonce, 8, 4) + 1) & 0xFFFF_FFFFL;
            ValidateUtils.checkState(counter != initialNonce, "Packet sequence number cannot be reused with the same key");
            BufferUtils.putUInt(counter, nonce, 8, 4);
            AlgorithmParameterSpec algorithmParameterSpec = new ChaCha20ParameterSpec(nonce, 0);
            bodyEngine.init(mode == Mode.Encrypt ? javax.crypto.Cipher.ENCRYPT_MODE : javax.crypto.Cipher.DECRYPT_MODE, k1, algorithmParameterSpec);
            init(mac, bodyEngine);
            headerEngine.init(mode == Mode.Encrypt ? javax.crypto.Cipher.ENCRYPT_MODE : javax.crypto.Cipher.DECRYPT_MODE, k2,
                    algorithmParameterSpec);
        }

        private void init(Mac mac, javax.crypto.Cipher engine) throws Exception {
            // Getting a full block from ChaCha20 increments its block counter (from 0 to 1), so the cipher
            // is set up correctly as a side-effect. The extra bytes gotten are simply discarded.
            //
            // Note that AbstractChaCha20Cipher.BLOCK_BYTES == 2 * Poly1305Mac.KEY_BYTES.
            byte[] block = new byte[Poly1305Mac.KEY_BYTES];
            engine.update(block, 0, block.length, block);
            mac.init(block);
            engine.update(block, 0, block.length, block);
        }
    }

}
