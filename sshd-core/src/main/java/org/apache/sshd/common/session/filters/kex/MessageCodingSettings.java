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
package org.apache.sshd.common.session.filters.kex;

import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.util.buffer.BufferUtils;

/**
 * Message encoding or decoding settings as determined at the end of a key exchange.
 */
public class MessageCodingSettings {

    private final Cipher cipher;

    private final Mac mac;

    private final Compression compression;

    private final Cipher.Mode mode;

    private byte[] key;

    private byte[] iv;

    public MessageCodingSettings(Cipher cipher, Mac mac, Compression compression, Cipher.Mode mode, byte[] key, byte[] iv) {
        this.cipher = cipher;
        this.mac = mac;
        this.compression = compression;
        this.mode = mode;
        this.key = key.clone();
        this.iv = iv.clone();
    }

    private void initCipher(long packetSequenceNumber) throws Exception {
        if (key != null) {
            if (cipher.getAlgorithm().startsWith("ChaCha")) {
                BufferUtils.putLong(packetSequenceNumber, iv, 0, iv.length);
            }
            cipher.init(mode, key, iv);
            key = null;
        }
    }

    /**
     * Get the {@link Cipher}.
     *
     * @param  packetSequenceNumber SSH packet sequence number for initializing the cipher. Pass {@link #seqo} if the
     *                              cipher is to be used for output, {@link #seqi} otherwise.
     * @return                      the fully initialized cipher
     * @throws Exception            if the cipher cannot be initialized
     */
    public Cipher getCipher(long packetSequenceNumber) throws Exception {
        initCipher(packetSequenceNumber);
        return cipher;
    }

    public Mac getMac() {
        return mac;
    }

    public Compression getCompression() {
        return compression;
    }
}
