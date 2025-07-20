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
package org.apache.sshd.common.util.security.eddsa.generic;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Utilities to extract the raw key bytes from ed25519 or ed448 public keys, in a manner that is independent of the
 * actual concrete key implementation classes.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class EdDSAUtils {

    private static final int ED25519_LENGTH = 32; // bytes

    private static final int ED448_LENGTH = 57; // bytes

    // These are the constant prefixes of X.509 encodings of ed25519 and ed448 keys. Appending the actual 32
    // or 57 key bytes yields valid encodings.

    // Sequence, length 42, Sequence, length 5, OID, length 3, O, I, D, Bit String, length 33, zero unused bits
    private static final byte[] ED25519_X509_PREFIX = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };
    // Sequence, length 67, Sequence, length 5, OID, length 3, O, I, D, Bit String, length 58, zero unused bits
    private static final byte[] ED448_X509_PREFIX = {
            0x30, 0x43, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x3a, 0x00 };

    private EdDSAUtils() {
        throw new IllegalStateException("No instantiation");
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data == null || prefix == null || prefix.length == 0 || data.length < prefix.length) {
            return false;
        }
        int unequal = 0;
        int length = prefix.length;
        for (int i = 0; i < length; i++) {
            unequal |= data[i] ^ prefix[i];
        }
        return unequal == 0;
    }

    /**
     * Retrieves the raw key bytes from an ed25519 or ed448 {@link PublicKey}.
     *
     * @param  key                 {@link PublicKey} to get the bytes of
     * @return                     the raw key bytes
     * @throws InvalidKeyException if the key is not an ed25519 or ed448 key, or if it doesn't use X.509 encoding
     */
    public static byte[] getBytes(PublicKey key) throws InvalidKeyException {
        // Extract the public key bytes from the X.509 encoding (last n bytes, depending on the OID).
        if (!"X.509".equalsIgnoreCase(key.getFormat())) {
            throw new InvalidKeyException("Cannot extract public key bytes from a non-X.509 encoding");
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException("Public key " + key.getClass().getCanonicalName() + " does not support encoding");
        }
        int n;
        if (encoded.length == ED25519_LENGTH + ED25519_X509_PREFIX.length && startsWith(encoded, ED25519_X509_PREFIX)) {
            n = ED25519_LENGTH;
        } else if (encoded.length == ED448_LENGTH + ED448_X509_PREFIX.length && startsWith(encoded, ED448_X509_PREFIX)) {
            n = ED448_LENGTH;
        } else {
            throw new InvalidKeyException("Public key is neither ed25519 nor ed448");
        }
        return Arrays.copyOfRange(encoded, encoded.length - n, encoded.length);
    }
}
