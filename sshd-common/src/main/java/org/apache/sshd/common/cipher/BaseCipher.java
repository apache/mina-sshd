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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Base class for all Cipher implementations delegating to the JCE provider.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BaseCipher implements Cipher {

    // For tests
    interface CipherFactory {
        javax.crypto.Cipher getCipher(String transformation) throws GeneralSecurityException;
    }

    static CipherFactory factory = SecurityUtils::getCipher;

    static boolean alwaysReInit;

    protected Mode mode;

    private javax.crypto.Cipher cipher;
    private final int ivsize;
    private final int authSize;
    private final int kdfSize;
    private final String algorithm;
    private final int keySize;
    private final int blkSize;
    private final String transformation;
    private String s;
    private SecretKey secretKey;

    public BaseCipher(int ivsize, int authSize, int kdfSize, String algorithm,
                      int keySize, String transformation, int blkSize) {
        this.ivsize = ivsize;
        this.authSize = authSize;
        this.kdfSize = kdfSize;
        this.algorithm = ValidateUtils.checkNotNullAndNotEmpty(algorithm, "No algorithm");
        this.keySize = keySize;
        this.transformation = ValidateUtils.checkNotNullAndNotEmpty(transformation, "No transformation");
        this.blkSize = blkSize;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getKeySize() {
        return keySize;
    }

    @Override
    public String getTransformation() {
        return transformation;
    }

    @Override
    public int getIVSize() {
        return ivsize;
    }

    @Override
    public int getAuthenticationTagSize() {
        return authSize;
    }

    @Override
    public int getKdfSize() {
        return kdfSize;
    }

    @Override
    public int getCipherBlockSize() {
        return blkSize;
    }

    @Override
    public void init(Mode mode, byte[] key, byte[] iv) throws Exception {
        key = initializeKeyData(mode, key, getKdfSize());
        iv = initializeIVData(mode, iv, getIVSize());
        cipher = createCipherInstance(mode, key, iv);
    }

    protected javax.crypto.Cipher getCipherInstance() {
        return cipher;
    }

    protected javax.crypto.Cipher createCipherInstance(Mode mode, byte[] key, byte[] iv) throws Exception {
        javax.crypto.Cipher instance = factory.getCipher(getTransformation());
        this.mode = mode;
        this.secretKey = new SecretKeySpec(key, getAlgorithm());
        instance.init(
                Mode.Encrypt.equals(mode)
                        ? javax.crypto.Cipher.ENCRYPT_MODE
                        : javax.crypto.Cipher.DECRYPT_MODE,
                secretKey,
                new IvParameterSpec(iv));
        return instance;
    }

    protected byte[] initializeKeyData(Mode mode, byte[] key, int reqLen) {
        return resize(key, reqLen);
    }

    protected byte[] initializeIVData(Mode mode, byte[] iv, int reqLen) {
        return resize(iv, reqLen);
    }

    @Override
    public void update(byte[] input, int inputOffset, int inputLen) throws Exception {
        try {
            int stored = cipher.update(input, inputOffset, inputLen, input, inputOffset);
            if (stored < inputLen || alwaysReInit) {
                // Cipher.update() may buffer. We need all. Call doFinal and re-init the cipher.
                // This works because in SSH inputLen is always a multiple of the cipher's block size.
                stored += cipher.doFinal(input, inputOffset + stored);
                // Now stored had better be inputLen
                if (stored != inputLen) {
                    throw new GeneralSecurityException(
                            "Cipher.doFinal() did not return all bytes: " + stored + " != " + inputLen);
                }
                reInit(input, inputOffset, inputLen);
            }
        } catch (GeneralSecurityException e) {
            // Add algorithm information
            throw new GeneralSecurityException(
                    "BaseCipher.update() for " + getTransformation() + '/' + getKeySize() + " failed (" + mode + ')', e);
        }
    }

    protected void reInit(byte[] processed, int offset, int length)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(Mode.Encrypt.equals(mode)
                ? javax.crypto.Cipher.ENCRYPT_MODE
                : javax.crypto.Cipher.DECRYPT_MODE,
                secretKey,
                determineNewParameters(processed, offset, length));
    }

    protected AlgorithmParameterSpec determineNewParameters(byte[] processed, int offset, int length) {
        // Default implementation; overridden as appropriate in subclasses
        throw new UnsupportedOperationException(getClass() + " needs to override determineNewParameters()");
    }

    @Override
    public void updateAAD(byte[] data, int offset, int length) throws Exception {
        throw new UnsupportedOperationException(getClass() + " does not support AAD operations");
    }

    protected static byte[] resize(byte[] data, int size) {
        if (data.length > size) {
            byte[] tmp = new byte[size];
            System.arraycopy(data, 0, tmp, 0, size);
            data = tmp;
        }
        return data;
    }

    @Override
    public String toString() {
        synchronized (this) {
            if (s == null) {
                s = getClass().getSimpleName()
                    + "[" + getAlgorithm()
                    + ", ivSize=" + getIVSize()
                    + ", kdfSize=" + getKdfSize()
                    + "," + getTransformation()
                    + ", blkSize=" + getCipherBlockSize()
                    + "]";
            }
        }

        return s;
    }
}
