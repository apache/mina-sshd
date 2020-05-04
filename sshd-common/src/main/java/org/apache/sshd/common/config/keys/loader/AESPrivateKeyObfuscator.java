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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Predicate;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.CipherInformation;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class AESPrivateKeyObfuscator extends AbstractPrivateKeyObfuscator {
    public static final String CIPHER_NAME = "AES";
    public static final AESPrivateKeyObfuscator INSTANCE = new AESPrivateKeyObfuscator();

    public AESPrivateKeyObfuscator() {
        super(CIPHER_NAME);
    }

    @Override
    public List<Integer> getSupportedKeySizes() {
        return getAvailableKeyLengths();
    }

    @Override
    public byte[] applyPrivateKeyCipher(
            byte[] bytes, PrivateKeyEncryptionContext encContext, boolean encryptIt)
            throws GeneralSecurityException, IOException {
        int keyLength = resolveKeyLength(encContext);
        byte[] keyValue = deriveEncryptionKey(encContext, keyLength / Byte.SIZE);
        return applyPrivateKeyCipher(bytes, encContext, keyLength, keyValue, encryptIt);
    }

    @Override
    protected int resolveInitializationVectorLength(PrivateKeyEncryptionContext encContext)
            throws GeneralSecurityException {
        int keyLength = resolveKeyLength(encContext);
        CipherInformation ci = resolveCipherInformation(keyLength, encContext.getCipherMode());
        if (ci == null) {
            throw new NoSuchAlgorithmException("No match found for " + encContext);
        }
        return ci.getIVSize();
    }

    protected CipherInformation resolveCipherInformation(int keyLength, String cipherMode) {
        Predicate<CipherInformation> selector = createCipherSelector(keyLength, cipherMode);
        return BuiltinCiphers.VALUES.stream()
                .filter(selector)
                .findFirst()
                .orElse(null);
    }

    @Override
    protected int resolveKeyLength(PrivateKeyEncryptionContext encContext) throws GeneralSecurityException {
        String cipherType = encContext.getCipherType();
        try {
            int keyLength = Integer.parseInt(cipherType);
            List<Integer> sizes = getSupportedKeySizes();
            for (Integer s : sizes) {
                if (s.intValue() == keyLength) {
                    return keyLength;
                }
            }

            throw new InvalidKeySpecException(
                    "Unknown " + getCipherName() + " key length: " + cipherType + " - supported: " + sizes);
        } catch (NumberFormatException e) {
            throw new InvalidKeySpecException(
                    "Bad " + getCipherName() + " key length (" + cipherType + "): " + e.getMessage(), e);
        }
    }

    /**
     * @return A {@link List} of {@link Integer}s holding the available key lengths values (in bits) for the JVM.
     *         <B>Note:</B> AES 256 requires special JCE policy extension installation (e.g., for Java 7 see
     *         <A HREF="http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html">this
     *         link</A>)
     */
    @SuppressWarnings("synthetic-access")
    public static List<Integer> getAvailableKeyLengths() {
        return LazyKeyLengthsHolder.KEY_LENGTHS;
    }

    public static Predicate<CipherInformation> createCipherSelector(int keyLength, String cipherMode) {
        String xformMode = "/" + cipherMode.toUpperCase() + "/";
        return c -> CIPHER_NAME.equalsIgnoreCase(c.getAlgorithm())
                && (keyLength == c.getKeySize())
                && c.getTransformation().contains(xformMode);
    }

    private static final class LazyKeyLengthsHolder {
        private static final List<Integer> KEY_LENGTHS = Collections.unmodifiableList(detectSupportedKeySizes());

        private LazyKeyLengthsHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }

        // AES 256 requires special JCE policy extension installation
        private static List<Integer> detectSupportedKeySizes() {
            List<Integer> sizes = new ArrayList<>();
            for (int keyLength = 128; keyLength < Short.MAX_VALUE /* just so it doesn't go forever */; keyLength += 64) {
                try {
                    byte[] keyAsBytes = new byte[keyLength / Byte.SIZE];
                    Key key = new SecretKeySpec(keyAsBytes, CIPHER_NAME);
                    Cipher c = SecurityUtils.getCipher(CIPHER_NAME);
                    c.init(Cipher.DECRYPT_MODE, key);
                    sizes.add(Integer.valueOf(keyLength));
                } catch (GeneralSecurityException e) {
                    return sizes;
                }
            }

            throw new IllegalStateException("No limit encountered: " + sizes);
        }
    }
}
