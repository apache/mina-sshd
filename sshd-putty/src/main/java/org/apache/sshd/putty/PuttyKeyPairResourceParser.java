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

package org.apache.sshd.putty;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.IdentityResourceLoader;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceParser;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

//CHECKSTYLE:OFF
/**
 * Loads a {@link KeyPair} from PuTTY's &quot;.ppk&quot; file.
 * <P>Note(s):</P>
 * <UL>
 *      <P><LI>
 *      The file appears to be a text file but it doesn't have a fixed encoding like UTF-8.
 *      We use UTF-8 as the default encoding - since the important part is all ASCII,
 *      this shouldn't really hurt the interpretation of the key.
 *      </LI></P>
 *
 *      <P><LI>
 *      Based on code from <A HREF="https://github.com/kohsuke/trilead-putty-extension">Kohsuke's Trilead Putty Extension</A>
 *      </LI></P>
 *
 *      <P><LI>
 *      Encrypted keys requires AES-256-CBC support, which is available only if the
 *      <A HREF="http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html">
 *      Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files</A> are installed
 *      </LI></P>
 * </UL>
 *
 * <P>Sample PuTTY file format</P>
 * <PRE>
 * PuTTY-User-Key-File-2: ssh-rsa
 * Encryption: none
 * Comment: rsa-key-20080514
 * Public-Lines: 4
 * AAAAB3NzaC1yc2EAAAABJQAAAIEAiPVUpONjGeVrwgRPOqy3Ym6kF/f8bltnmjA2
 * BMdAtaOpiD8A2ooqtLS5zWYuc0xkW0ogoKvORN+RF4JI+uNUlkxWxnzJM9JLpnvA
 * HrMoVFaQ0cgDMIHtE1Ob1cGAhlNInPCRnGNJpBNcJ/OJye3yt7WqHP4SPCCLb6nL
 * nmBUrLM=
 * Private-Lines: 8
 * AAAAgGtYgJzpktzyFjBIkSAmgeVdozVhgKmF6WsDMUID9HKwtU8cn83h6h7ug8qA
 * hUWcvVxO201/vViTjWVz9ALph3uMnpJiuQaaNYIGztGJBRsBwmQW9738pUXcsUXZ
 * 79KJP01oHn6Wkrgk26DIOsz04QOBI6C8RumBO4+F1WdfueM9AAAAQQDmA4hcK8Bx
 * nVtEpcF310mKD3nsbJqARdw5NV9kCxPnEsmy7Sy1L4Ob/nTIrynbc3MA9HQVJkUz
 * 7V0va5Pjm/T7AAAAQQCYbnG0UEekwk0LG1Hkxh1OrKMxCw2KWMN8ac3L0LVBg/Tk
 * 8EnB2oT45GGeJaw7KzdoOMFZz0iXLsVLNUjNn2mpAAAAQQCN6SEfWqiNzyc/w5n/
 * lFVDHExfVUJp0wXv+kzZzylnw4fs00lC3k4PZDSsb+jYCMesnfJjhDgkUA0XPyo8
 * Emdk
 * Private-MAC: 50c45751d18d74c00fca395deb7b7695e3ed6f77
 * </PRE>
 * @param <PUB> Generic public key type
 * @param <PRV> Generic private key type
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
//CHECKSTYLE:ON
public interface PuttyKeyPairResourceParser<PUB extends PublicKey, PRV extends PrivateKey>
        extends IdentityResourceLoader<PUB, PRV>, KeyPairResourceParser {
    String KEY_FILE_HEADER_PREFIX = "PuTTY-User-Key-File";
    String PUBLIC_LINES_HEADER = "Public-Lines";
    String PRIVATE_LINES_HEADER = "Private-Lines";
    String PPK_FILE_SUFFIX = ".ppk";

    List<String> KNOWN_HEADERS = Collections.unmodifiableList(
            Arrays.asList(
                    KEY_FILE_HEADER_PREFIX,
                    PUBLIC_LINES_HEADER,
                    PRIVATE_LINES_HEADER));

    /**
     * Value (case insensitive) used to denote that private key is not encrypted
     */
    String NO_PRIVATE_KEY_ENCRYPTION_VALUE = "none";

    @Override
    default boolean canExtractKeyPairs(NamedResource resourceKey, List<String> lines)
            throws IOException, GeneralSecurityException {
        if (GenericUtils.isEmpty(lines)) {
            return false;
        }

        for (String l : lines) {
            l = GenericUtils.trimToEmpty(l);
            for (String hdr : KNOWN_HEADERS) {
                if (l.startsWith(hdr)) {
                    return true;
                }
            }
        }

        return false;
    }

    static byte[] decodePrivateKeyBytes(
            byte[] prvBytes, String algName, int numBits, String algMode, String password)
            throws GeneralSecurityException {
        Objects.requireNonNull(prvBytes, "No encrypted key bytes");
        ValidateUtils.checkNotNullAndNotEmpty(algName, "No encryption algorithm", GenericUtils.EMPTY_OBJECT_ARRAY);
        ValidateUtils.checkTrue(numBits > 0, "Invalid encryption key size: %d", numBits);
        ValidateUtils.checkNotNullAndNotEmpty(algMode, "No encryption mode", GenericUtils.EMPTY_OBJECT_ARRAY);
        ValidateUtils.checkNotNullAndNotEmpty(password, "No encryption password", GenericUtils.EMPTY_OBJECT_ARRAY);

        if (!"AES".equalsIgnoreCase(algName)) {
            throw new NoSuchAlgorithmException("decodePrivateKeyBytes(" + algName + "-" + numBits + "-" + algMode + ") N/A");
        }

        byte[] initVector = new byte[16];
        byte[] keyValue = toEncryptionKey(password);
        try {
            return decodePrivateKeyBytes(prvBytes, algName, algMode, numBits, initVector, keyValue);
        } finally {
            Arrays.fill(initVector, (byte) 0); // eliminate sensitive data a.s.a.p.
            Arrays.fill(keyValue, (byte) 0); // eliminate sensitive data a.s.a.p.
        }
    }

    static byte[] decodePrivateKeyBytes(
            byte[] encBytes, String cipherName, String cipherMode, int numBits, byte[] initVector, byte[] keyValue)
            throws GeneralSecurityException {
        String xform = cipherName + "/" + cipherMode + "/NoPadding";
        int maxAllowedBits = Cipher.getMaxAllowedKeyLength(xform);
        // see http://www.javamex.com/tutorials/cryptography/unrestricted_policy_files.shtml
        if (numBits > maxAllowedBits) {
            throw new InvalidKeySpecException(
                    "decodePrivateKeyBytes(" + xform + ")"
                                              + " required key length (" + numBits + ") exceeds max. available: "
                                              + maxAllowedBits);
        }

        SecretKeySpec skeySpec = new SecretKeySpec(keyValue, cipherName);
        IvParameterSpec ivspec = new IvParameterSpec(initVector);
        Cipher cipher = SecurityUtils.getCipher(xform);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivspec);

        return cipher.doFinal(encBytes);
    }

    /**
     * Converts a pass-phrase into a key, by following the convention that PuTTY uses. Used to decrypt the private key
     * when it's encrypted.
     * 
     * @param  passphrase               the Password to be used as seed for the key - ignored if {@code null}/empty
     * @return                          The encryption key bytes - {@code null/empty} if no pass-phrase
     * @throws GeneralSecurityException If cannot retrieve SHA-1 digest
     * @see                             <A HREF=
     *                                  "http://security.stackexchange.com/questions/71341/how-does-putty-derive-the-encryption-key-in-its-ppk-format">
     *                                  How does Putty derive the encryption key in its .ppk format ?</A>
     */
    static byte[] toEncryptionKey(String passphrase) throws GeneralSecurityException {
        if (GenericUtils.isEmpty(passphrase)) {
            return GenericUtils.EMPTY_BYTE_ARRAY;
        }

        byte[] passBytes = passphrase.getBytes(StandardCharsets.UTF_8);
        try {
            MessageDigest hash = SecurityUtils.getMessageDigest(BuiltinDigests.sha1.getAlgorithm());
            byte[] stateValue = { 0, 0, 0, 0 };
            byte[] keyValue = new byte[32];
            try {
                for (int i = 0, remLen = keyValue.length; i < 2; i++) {
                    hash.reset(); // just making sure

                    stateValue[3] = (byte) i;
                    hash.update(stateValue);
                    hash.update(passBytes);

                    byte[] digest = hash.digest();
                    try {
                        System.arraycopy(digest, 0, keyValue, i * 20, Math.min(20, remLen));
                    } finally {
                        Arrays.fill(digest, (byte) 0); // eliminate sensitive data a.s.a.p.
                    }
                    remLen -= 20;
                }
            } finally {
                Arrays.fill(stateValue, (byte) 0); // eliminate sensitive data a.s.a.p.
            }

            return keyValue;
        } finally {
            Arrays.fill(passBytes, (byte) 0); // eliminate sensitive data a.s.a.p.
        }
    }
}
