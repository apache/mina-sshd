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

package org.apache.sshd.common.config.keys.loader.openssh;

import static java.text.MessageFormat.format;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.function.Predicate;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class OpenSSHParserContext {
    public static final String NONE_CIPHER = "none";
    public static final Predicate<String> IS_NONE_CIPHER = c -> GenericUtils.isEmpty(c) || NONE_CIPHER.equalsIgnoreCase(c);

    public static final String NONE_KDF = "none";
    public static final Predicate<String> IS_NONE_KDF = c -> GenericUtils.isEmpty(c) || NONE_KDF.equalsIgnoreCase(c);

    public static final String BCRYPT_KDF = "bcrypt";

    private final String cipherName;
    private final String kdfName;

    private final BuiltinCiphers cipherSpec;
    private final byte[] salt;
    private final int rounds;

    /**
     * Creates a new context. Accepts the {@link #NONE_CIPHER} with the
     * {@link #NONE_KDF}, or other ciphers with the {@link #BCRYPT_KDF}.
     *
     * @param resourceKey
     *            identifies the key resource this context is for
     * @param cipherName
     *            as extracted from the key resource
     * @param kdfName
     *            as extracted from the key resource
     * @param kdfOptions
     *            as extracted from the key resource
     * @throws IOException
     *             if the {@link #BCRYPT_KDF} is specified but no bcrypt
     *             parameters can be extracted from {@code kdfOptions}
     * @throws NoSuchAlgorithmException
     *             if unknown or inconsistent cipher or KDF are specified
     */
    public OpenSSHParserContext(NamedResource resourceKey, String cipherName, String kdfName, byte... kdfOptions)
            throws IOException, NoSuchAlgorithmException {
        this.cipherName = cipherName;
        this.kdfName = kdfName;
        if (IS_NONE_CIPHER.test(cipherName)) {
            if (!IS_NONE_KDF.test(kdfName)) {
                throw new NoSuchAlgorithmException(format("No key derivation function allowed in un-encrypted key {0}", resourceKey.getName()));
            }
            cipherSpec = null;
            salt = null;
            rounds = 0;
        } else {
            if (IS_NONE_KDF.test(kdfName)) {
                throw new NoSuchAlgorithmException(format("No key derivation function in encrypted key {0}", resourceKey.getName()));
            }
            if (!BCRYPT_KDF.equalsIgnoreCase(kdfName)) {
                throw new NoSuchAlgorithmException(format("Unknown key derivation function ''{0}'' in encrypted key {1}", kdfName, resourceKey.getName()));
            }
            // Find the cipher.
            cipherSpec = BuiltinCiphers.fromFactoryName(cipherName);
            if (cipherSpec == null || !cipherSpec.isSupported()) {
                throw new NoSuchAlgorithmException(format("Unknown cipher ''{0}'' in encrypted key {1}", cipherName, resourceKey.getName()));
            }
            // Extract the bcrypt parameters from kdfOptions.
            if (GenericUtils.isEmpty(kdfOptions)) {
                throw new StreamCorruptedException(format("No bcrypt parameters in encrypted key {0}", resourceKey.getName()));
            }
            try (InputStream input = new ByteArrayInputStream(kdfOptions)) {
                // Minus 8: 4 bytes for the RLE of the salt itself, plus 4 bytes for the rounds.
                int expectedLength = kdfOptions.length - 8;
                salt = KeyEntryResolver.readRLEBytes(input, expectedLength);
                if (salt.length != expectedLength) {
                    throw new StreamCorruptedException(format("Invalid bcrypt salt in encrypted key {0}", resourceKey.getName()));
                }
                // OpenSSH stores the number of rounds, not the cost factor (exponent).
                // It would be possible to have non-power-of-two rounds.
                rounds = KeyEntryResolver.decodeInt(input);
                if (rounds == 0) {
                    throw new StreamCorruptedException(format("Bcrypt rounds is zero in encrypted key {0}", resourceKey.getName()));
                } else if (rounds < 0) {
                    // The Java implementation of BCrypt cannot handle rounds > (2**31)-1.
                    throw new StreamCorruptedException(format("Bcrypt rounds is too large in encrypted key {0}", resourceKey.getName()));
                }
            }
        }
    }

    /**
     * Determines whether this context is for an encrypted key resource.
     *
     * @return {@code true} if decryption will be applied, {@code false}
     *         otherwise.
     */
    public boolean isEncrypted() {
        return cipherSpec != null;
    }

    /**
     * Validates the raw private key data.
     *
     * @param data
     *            to check
     * @return {@code true} if the data is not encrypted or otherwise valid to
     *         be passed to {@link #decrypt(byte[], byte[])}; {@code false}
     *         otherwise, including if {@code data} is empty
     */
    public boolean validate(byte[] data) {
        if (data == null || data.length == 0) {
            return false;
        }
        if (isEncrypted()) {
            int blockSize = cipherSpec.getCipherBlockSize();
            return data.length % blockSize == 0;
        }
        return true;
    }

    /**
     * Decrypts {@code original} bytes extracted from a key resource and returns
     * the decrypted bytes. Returns {@code original} if no encryption was
     * specified, or if it is empty.
     * <p>
     * The {@code password} array is <em>not</em> cleared; the caller is
     * reponsible for doing so.
     * </p>
     *
     * @param original
     *            bytes to decode
     * @param password
     *            to use for decryption
     * @return the decrypted bytes in a new array, or {@code original} if no
     *         encryption was applied
     * @throws GeneralSecurityException
     *             if the data cannot be decrypted
     */
    public byte[] decrypt(byte[] original, byte[] password)
            throws GeneralSecurityException {
        if (!isEncrypted() || GenericUtils.isEmpty(original)) {
            return original;
        }
        byte[] cipherInput = null;
        try {
            // Get cipher key & IV sizes.
            int keySize = cipherSpec.getKdfSize();
            int ivSize = cipherSpec.getIVSize();
            // Use KDF over password to generate key & IV for cipher.
            cipherInput = new byte[keySize + ivSize];
            bcryptKdf(password, cipherInput);
            // Set key & IV of cipher.
            Cipher cipher = SecurityUtils.getCipher(cipherSpec.getTransformation());
            SecretKeySpec key = new SecretKeySpec(Arrays.copyOfRange(cipherInput, 0, keySize), cipherSpec.getAlgorithm());
            IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(cipherInput, keySize, cipherInput.length));
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            return cipher.doFinal(original);
        } finally {
            if (cipherInput != null) {
                Arrays.fill(cipherInput, (byte) 0);
            }
        }
    }

    private void bcryptKdf(byte[] password, byte[] toGenerate)
            throws GeneralSecurityException {
        try {
            BCrypt bcrypt = new BCrypt();
            bcrypt.pbkdf(password, salt, rounds, toGenerate);
        } catch (RuntimeException e) {
            if (e.getCause() instanceof GeneralSecurityException) {
                throw (GeneralSecurityException) e.getCause();
            }
            throw e;
        }
    }

    public String getCipherName() {
        return cipherName;
    }

    public String getKdfName() {
        return kdfName;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
            + "[cipher=" + getCipherName()
            + ", kdfName=" + getKdfName()
            + ", kdfOptions=" + (salt == null ? "null" : (BufferUtils.toHex(':', salt) + '/' + Integer.toString(rounds)))
            + "]";
    }
}
