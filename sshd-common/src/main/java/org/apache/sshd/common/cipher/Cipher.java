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

import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Wrapper for a cryptographic cipher, used either for encryption or decryption.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Cipher extends CipherInformation {

    enum Mode {
        Encrypt,
        Decrypt
    }

    /**
     * Initialize the cipher for encryption or decryption with the given key and initialization vector
     *
     * @param  mode      Encrypt/Decrypt initialization
     * @param  key       Key bytes
     * @param  iv        Initialization vector bytes
     * @throws Exception If failed to initialize
     */
    void init(Mode mode, byte[] key, byte[] iv) throws Exception;

    /**
     * Performs in-place encryption or decryption on the given data.
     *
     * @param  input     The input/output bytes
     * @throws Exception If failed to execute
     * @see              #update(byte[], int, int)
     */
    default void update(byte[] input) throws Exception {
        update(input, 0, NumberUtils.length(input));
    }

    /**
     * Performs in-place encryption or decryption on the given data.
     *
     * @param  input       The input/output bytes
     * @param  inputOffset The offset of the data in the data buffer
     * @param  inputLen    The number of bytes to update - starting at the given offset
     * @throws Exception   If failed to execute
     */
    void update(byte[] input, int inputOffset, int inputLen) throws Exception;

    /**
     * Adds the provided input data as additional authenticated data during encryption or decryption.
     *
     * @param  data      The data to authenticate
     * @throws Exception If failed to execute
     */
    default void updateAAD(byte[] data) throws Exception {
        updateAAD(data, 0, NumberUtils.length(data));
    }

    /**
     * Adds the provided input data as additional authenticated data during encryption or decryption.
     *
     * @param  data      The additional data to authenticate
     * @param  offset    The offset of the additional data in the buffer
     * @param  length    The number of bytes in the buffer to use for authentication
     * @throws Exception If failed to execute
     */
    void updateAAD(byte[] data, int offset, int length) throws Exception;

    /**
     * Performs in-place authenticated encryption or decryption with additional data (AEAD). Authentication tags are
     * implicitly appended after the output ciphertext or implicitly verified after the input ciphertext. Header data
     * indicated by the {@code aadLen} parameter are authenticated but not encrypted/decrypted, while payload data
     * indicated by the {@code inputLen} parameter are authenticated and encrypted/decrypted.
     *
     * @param  input     The input/output bytes
     * @param  offset    The offset of the data in the input buffer
     * @param  aadLen    The number of bytes to use as additional authenticated data - starting at offset
     * @param  inputLen  The number of bytes to update - starting at offset + aadLen
     * @throws Exception If failed to execute
     */
    default void updateWithAAD(byte[] input, int offset, int aadLen, int inputLen) throws Exception {
        updateAAD(input, offset, aadLen);
        update(input, offset + aadLen, inputLen);
    }

    /**
     * @param  xform     The full cipher transformation - e.g., AES/CBC/NoPadding - never {@code null}/empty
     * @param  keyLength The required key length in bits - always positive
     * @return           {@code true} if the cipher transformation <U>and</U> required key length are supported
     * @see              javax.crypto.Cipher#getMaxAllowedKeyLength(String)
     */
    static boolean checkSupported(String xform, int keyLength) {
        ValidateUtils.checkNotNullAndNotEmpty(xform, "No transformation");
        if (keyLength <= 0) {
            throw new IllegalArgumentException("Bad key length (" + keyLength + ") for cipher=" + xform);
        }

        try {
            int maxKeyLength = javax.crypto.Cipher.getMaxAllowedKeyLength(xform);
            return maxKeyLength >= keyLength;
        } catch (Exception e) {
            return false;
        }
    }
}
