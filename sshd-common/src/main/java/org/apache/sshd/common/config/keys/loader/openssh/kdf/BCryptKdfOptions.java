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

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.CipherFactory;
import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.config.keys.loader.openssh.OpenSSHKdfOptions;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BCryptKdfOptions implements OpenSSHKdfOptions {
    public static final String NAME = "bcrypt";
    /*
     * Since each round doubles its predecessor, the Java implementation
     * of BCrypt cannot handle rounds > (2^31) - 1
     */
    public static final int MAX_ROUNDS = 31;

    private byte[] salt;
    private int numRounds;

    public BCryptKdfOptions() {
        super();
    }

    /**
     * @param stream <P>Assumed to contain the encoded KDF options:</P></BR>
     * <pre><code>
     *      string salt
     *      uint32 rounds
     * </code></pre>
     * @throws IOException If failed to decode
     * @see <A HREF="http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key?rev=1.1&content-type=text/x-cvsweb-markup">Section 2</A>
     */
    public BCryptKdfOptions(InputStream stream) throws IOException {
        initialize(stream);
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
        int expectedSaltLength = kdfOptions.length - 8;
        try (InputStream stream = new ByteArrayInputStream(kdfOptions)) {
            initialize(stream, expectedSaltLength);
        }

        byte[] saltValue = getSalt();
        int actualSaltLength = NumberUtils.length(saltValue);
        if (actualSaltLength != expectedSaltLength) {
            throw new StreamCorruptedException("Mismatched salt data length:"
                + " expected=" + expectedSaltLength + ", actual=" + actualSaltLength);
        }
    }

    /**
     * @param stream <P>Assumed to contain the encoded KDF options:</P></BR>
     * <PRE><CODE>
     *      string salt
     *      uint32 rounds
     * </CODE></PRE>
     * @throws IOException If failed to decode
     * @see <A HREF="http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key?rev=1.1&content-type=text/x-cvsweb-markup">Section 2</A>
     */
    public void initialize(InputStream stream) throws IOException {
        initialize(stream, OpenSSHKdfOptions.MAX_KDF_OPTIONS_SIZE);
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
            throw new StreamCorruptedException("Encrypted data size (" + privateDataBytes.length + ")"
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
        } finally {
            Arrays.fill(pwd, (byte) 0); // Don't keep password data in memory longer than necessary
            Arrays.fill(cipherInput, (byte) 0); // Don't keep cipher data in memory longer than necessary
        }
    }

    protected void bcryptKdf(byte[] password, byte[] output) throws IOException, GeneralSecurityException {
        throw new NoSuchAlgorithmException("Unsupported KDF (" + this + ")");
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
        ValidateUtils.checkTrue((numRounds >= 0) && (numRounds <= MAX_ROUNDS), "Invalid rounds count: %d", numRounds);
        this.numRounds = numRounds;
    }

    @Override
    public int hashCode() {
        return 31 * getNumRounds() +  Arrays.hashCode(getSalt());
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

}
