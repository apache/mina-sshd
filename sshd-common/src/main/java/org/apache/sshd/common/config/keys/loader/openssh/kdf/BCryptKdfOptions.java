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

package org.apache.sshd.common.config.keys.loader.openssh.kdf;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.CipherFactory;
import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.config.keys.loader.openssh.OpenSSHKdfOptions;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BCryptKdfOptions implements OpenSSHKdfOptions {
    public static final String NAME = "bcrypt";

    /**
     * Various discussions on the net seem to indicate that 64 is the value at which many computers seem to slow down
     * noticeably, so we are rather generous here. The default value (unless overridden by the {@code -a} parameter to
     * the {@code ssh-keygen} command) is usually 16.
     */
    public static final int DEFAULT_MAX_ROUNDS = 0xFF;
    private static final AtomicInteger MAX_ROUNDS_HOLDER = new AtomicInteger(DEFAULT_MAX_ROUNDS);

    private byte[] salt;
    private int numRounds;

    public BCryptKdfOptions() {
        super();
    }

    @Override
    public void initialize(String name, byte[] kdfOptions) throws IOException {
        if (!NAME.equalsIgnoreCase(name)) {
            throw new StreamCorruptedException("Mismatched KDF name: " + name);
        }

        if (NumberUtils.isEmpty(kdfOptions)) {
            throw new StreamCorruptedException("Missing KDF options for " + name);
        }

        // Minus 8: 4 bytes for the RLE of the salt itself, plus 4 bytes for the rounds
        int expectedSaltLength = kdfOptions.length - 2 * Integer.BYTES;
        try (InputStream stream = new ByteArrayInputStream(kdfOptions)) {
            initialize(stream, expectedSaltLength);
        }

        byte[] saltValue = getSalt();
        int actualSaltLength = NumberUtils.length(saltValue);
        if (actualSaltLength != expectedSaltLength) {
            throw new StreamCorruptedException(
                    "Mismatched salt data length:"
                                               + " expected=" + expectedSaltLength + ", actual=" + actualSaltLength);
        }
    }

    protected void initialize(InputStream stream, int maxSaltSize) throws IOException {
        setSalt(KeyEntryResolver.readRLEBytes(stream, maxSaltSize));
        setNumRounds(KeyEntryResolver.decodeInt(stream));
    }

    @Override
    public boolean isEncrypted() {
        return true;
    }

    @Override
    public byte[] decodePrivateKeyBytes(
            SessionContext session, NamedResource resourceKey, String cipherName, byte[] privateDataBytes, String password)
            throws IOException, GeneralSecurityException {
        if (NumberUtils.isEmpty(privateDataBytes)) {
            return privateDataBytes;
        }

        CipherFactory cipherSpec = BuiltinCiphers.resolveFactory(cipherName);
        if ((cipherSpec == null) || (!cipherSpec.isSupported())) {
            throw new NoSuchAlgorithmException("Unsupported cipher: " + cipherName);
        }

        int blockSize = cipherSpec.getCipherBlockSize();
        if ((privateDataBytes.length % blockSize) != 0) {
            throw new StreamCorruptedException(
                    "Encrypted data size (" + privateDataBytes.length + ")"
                                               + " is not aligned to  " + cipherName + " block size (" + blockSize + ")");
        }

        byte[] pwd = password.getBytes(StandardCharsets.UTF_8);
        // Get cipher key & IV sizes.
        int keySize = cipherSpec.getKdfSize();
        int ivSize = cipherSpec.getIVSize();
        byte[] cipherInput = new byte[keySize + ivSize];
        try {
            bcryptKdf(pwd, cipherInput);

            byte[] kv = Arrays.copyOfRange(cipherInput, 0, keySize);
            byte[] iv = Arrays.copyOfRange(cipherInput, keySize, cipherInput.length);
            try {
                Cipher cipher = SecurityUtils.getCipher(cipherSpec.getTransformation());
                SecretKeySpec keySpec = new SecretKeySpec(kv, cipherSpec.getAlgorithm());
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
                return cipher.doFinal(privateDataBytes);
            } finally {
                // Don't keep cipher data in memory longer than necessary
                Arrays.fill(kv, (byte) 0);
                Arrays.fill(iv, (byte) 0);
            }
        } catch (RuntimeException e) {
            Throwable t = GenericUtils.peelException(e);
            Throwable err = null;
            if ((t instanceof IOException) || (t instanceof GeneralSecurityException)) {
                err = t;
            } else {
                t = GenericUtils.resolveExceptionCause(e);
                if ((t instanceof IOException) || (t instanceof GeneralSecurityException)) {
                    err = t;
                }
            }

            if (err instanceof IOException) {
                throw (IOException) err;
            } else if (err instanceof GeneralSecurityException) {
                throw (GeneralSecurityException) err;
            } else {
                throw e;
            }
        } finally {
            Arrays.fill(pwd, (byte) 0); // Don't keep password data in memory longer than necessary
            Arrays.fill(cipherInput, (byte) 0); // Don't keep cipher data in memory longer than necessary
        }
    }

    protected void bcryptKdf(byte[] password, byte[] output) throws IOException, GeneralSecurityException {
        BCrypt bcrypt = new BCrypt();
        bcrypt.pbkdf(password, getSalt(), getNumRounds(), output);
    }

    @Override
    public final String getName() {
        return NAME;
    }

    public byte[] getSalt() {
        return NumberUtils.emptyIfNull(salt);
    }

    public void setSalt(byte[] salt) {
        this.salt = NumberUtils.emptyIfNull(salt);
    }

    public int getNumRounds() {
        return numRounds;
    }

    public void setNumRounds(int numRounds) {
        int maxAllowed = getMaxAllowedRounds();
        if ((numRounds <= 0) || (numRounds > maxAllowed)) {
            throw new BCryptBadRoundsException(
                    numRounds, "Bad rounds value (" + numRounds + ") - max. allowed " + maxAllowed);
        }

        this.numRounds = numRounds;
    }

    @Override
    public int hashCode() {
        return 31 * getNumRounds() + Arrays.hashCode(getSalt());
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }

        BCryptKdfOptions other = (BCryptKdfOptions) obj;
        return (getNumRounds() == other.getNumRounds())
                && Arrays.equals(getSalt(), other.getSalt());
    }

    @Override
    public String toString() {
        return getName() + ": rounds=" + getNumRounds() + ", salt=" + BufferUtils.toHex(':', getSalt());
    }

    public static int getMaxAllowedRounds() {
        return MAX_ROUNDS_HOLDER.get();
    }

    public static void setMaxAllowedRounds(int value) {
        ValidateUtils.checkTrue(value > 0, "Invalid max. rounds value: %d", value);
        MAX_ROUNDS_HOLDER.set(value);
    }

    public static class BCryptBadRoundsException extends RuntimeSshException {
        private static final long serialVersionUID = 1724985268892193553L;
        private final int rounds;

        public BCryptBadRoundsException(int rounds) {
            this(rounds, "Bad rounds value: " + rounds);
        }

        public BCryptBadRoundsException(int rounds, String message) {
            this(rounds, message, null);
        }

        public BCryptBadRoundsException(int rounds, String message, Throwable reason) {
            super(message, reason);
            this.rounds = rounds;
        }

        public int getRounds() {
            return rounds;
        }
    }
}
