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
package org.apache.sshd.common.config.keys.loader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractPrivateKeyObfuscator implements PrivateKeyObfuscator {
    private final String algName;

    protected AbstractPrivateKeyObfuscator(String name) {
        algName = ValidateUtils.checkNotNullAndNotEmpty(name, "No name specified");
    }

    @Override
    public final String getCipherName() {
        return algName;
    }

    @Override
    public byte[] generateInitializationVector(PrivateKeyEncryptionContext encContext)
            throws GeneralSecurityException {
        int ivSize = resolveInitializationVectorLength(encContext);
        byte[] initVector = new byte[ivSize];
        Random randomizer = new SecureRandom(); // TODO consider using some pre-created singleton instance
        randomizer.nextBytes(initVector);
        return initVector;
    }

    @Override
    public <A extends Appendable> A appendPrivateKeyEncryptionContext(
            A sb, PrivateKeyEncryptionContext encContext)
            throws IOException {
        if (encContext == null) {
            return sb;
        }

        sb.append("DEK-Info: ").append(encContext.getCipherName())
                .append('-').append(encContext.getCipherType())
                .append('-').append(encContext.getCipherMode());

        byte[] initVector = encContext.getInitVector();
        Objects.requireNonNull(initVector, "No encryption init vector");
        ValidateUtils.checkTrue(initVector.length > 0, "Empty encryption init vector");
        BufferUtils.appendHex(sb.append(','), BufferUtils.EMPTY_HEX_SEPARATOR, initVector);
        sb.append(System.lineSeparator());
        return sb;
    }

    protected abstract int resolveInitializationVectorLength(PrivateKeyEncryptionContext encContext)
            throws GeneralSecurityException;

    protected abstract int resolveKeyLength(PrivateKeyEncryptionContext encContext) throws GeneralSecurityException;

    // see http://martin.kleppmann.com/2013/05/24/improving-security-of-ssh-private-keys.html
    // see http://www.ict.griffith.edu.au/anthony/info/crypto/openssl.hints (Password to Encryption Key section)
    // see http://openssl.6102.n7.nabble.com/DES-EDE3-CBC-technical-details-td24883.html
    protected byte[] deriveEncryptionKey(PrivateKeyEncryptionContext encContext, int outputKeyLength)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(encContext, "No encryption context");
        ValidateUtils.checkNotNullAndNotEmpty(encContext.getCipherName(), "No cipher name");
        ValidateUtils.checkNotNullAndNotEmpty(encContext.getCipherType(), "No cipher type");
        ValidateUtils.checkNotNullAndNotEmpty(encContext.getCipherMode(), "No cipher mode");

        byte[] initVector = Objects.requireNonNull(encContext.getInitVector(), "No encryption init vector");
        ValidateUtils.checkTrue(initVector.length > 0, "Empty encryption init vector");

        String password = ValidateUtils.checkNotNullAndNotEmpty(encContext.getPassword(), "No encryption password");
        byte[] passBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] prevHash = GenericUtils.EMPTY_BYTE_ARRAY;
        try {
            byte[] keyValue = new byte[outputKeyLength];
            MessageDigest hash = SecurityUtils.getMessageDigest(BuiltinDigests.Constants.MD5);
            for (int index = 0, remLen = keyValue.length; index < keyValue.length;) {
                hash.reset(); // just making sure

                hash.update(prevHash, 0, prevHash.length);
                hash.update(passBytes, 0, passBytes.length);
                hash.update(initVector, 0, Math.min(initVector.length, 8));

                prevHash = hash.digest();

                System.arraycopy(prevHash, 0, keyValue, index, Math.min(remLen, prevHash.length));
                index += prevHash.length;
                remLen -= prevHash.length;
            }

            return keyValue;
        } finally {
            password = null;
            Arrays.fill(passBytes, (byte) 0); // clean up sensitive data a.s.a.p.
            Arrays.fill(prevHash, (byte) 0); // clean up sensitive data a.s.a.p.
        }
    }

    protected byte[] applyPrivateKeyCipher(
            byte[] bytes, PrivateKeyEncryptionContext encContext, int numBits, byte[] keyValue, boolean encryptIt)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(encContext, "No encryption context");
        String cipherName = ValidateUtils.checkNotNullAndNotEmpty(encContext.getCipherName(), "No cipher name");
        ValidateUtils.checkNotNullAndNotEmpty(encContext.getCipherType(), "No cipher type");
        String cipherMode = ValidateUtils.checkNotNullAndNotEmpty(encContext.getCipherMode(), "No cipher mode");

        Objects.requireNonNull(bytes, "No source data");
        Objects.requireNonNull(keyValue, "No encryption key");
        ValidateUtils.checkTrue(keyValue.length > 0, "Empty encryption key");

        byte[] initVector = Objects.requireNonNull(encContext.getInitVector(), "No encryption init vector");
        ValidateUtils.checkTrue(initVector.length > 0, "Empty encryption init vector");

        String xform = cipherName + "/" + cipherMode + "/NoPadding";
        int maxAllowedBits = Cipher.getMaxAllowedKeyLength(xform);
        // see http://www.javamex.com/tutorials/cryptography/unrestricted_policy_files.shtml
        if (numBits > maxAllowedBits) {
            throw new InvalidKeySpecException(
                    "applyPrivateKeyCipher(" + xform + ")[encrypt=" + encryptIt + "]"
                                              + " required key length (" + numBits + ")"
                                              + " exceeds max. available: " + maxAllowedBits);
        }

        SecretKeySpec skeySpec = new SecretKeySpec(keyValue, cipherName);
        IvParameterSpec ivspec = new IvParameterSpec(initVector);
        Cipher cipher = SecurityUtils.getCipher(xform);
        int blockSize = cipher.getBlockSize();
        int dataSize = bytes.length;
        cipher.init(encryptIt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, skeySpec, ivspec);
        if (blockSize <= 0) {
            return cipher.doFinal(bytes);
        }

        int remLen = dataSize % blockSize;
        if (remLen <= 0) {
            return cipher.doFinal(bytes);
        }

        int updateSize = dataSize - remLen;
        byte[] lastBlock = new byte[blockSize];

        // TODO for some reason, calling cipher.update followed by cipher.doFinal does not work
        ByteArrayOutputStream baos = new ByteArrayOutputStream(dataSize);
        try {
            Arrays.fill(lastBlock, (byte) 10);
            System.arraycopy(bytes, updateSize, lastBlock, 0, remLen);

            try {
                byte[] buf = cipher.update(bytes, 0, updateSize);
                try {
                    baos.write(buf);
                } finally {
                    Arrays.fill(buf, (byte) 0); // get rid of sensitive data a.s.a.p.
                }

                buf = cipher.doFinal(lastBlock);
                try {
                    baos.write(buf);
                } finally {
                    Arrays.fill(buf, (byte) 0); // get rid of sensitive data a.s.a.p.
                }
            } finally {
                baos.close();
            }
        } finally {
            Arrays.fill(lastBlock, (byte) 0);
        }

        return baos.toByteArray();
    }
}
