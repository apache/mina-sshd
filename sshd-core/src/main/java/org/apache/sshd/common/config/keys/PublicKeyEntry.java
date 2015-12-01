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

package org.apache.sshd.common.config.keys;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.StreamCorruptedException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Objects;

import org.apache.sshd.common.util.Base64;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;

/**
 * <P>Represents a {@link PublicKey} whose data is formatted according to
 * the <A HREF="http://en.wikibooks.org/wiki/OpenSSH">OpenSSH</A> format:</P>
 *
 * <PRE>
 * &lt;key-type&gt; &lt;base64-encoded-public-key-data&gt;
 * </PRE>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PublicKeyEntry implements Serializable {

    /**
     * Character used to denote a comment line in the keys file
     */
    public static final char COMMENT_CHAR = '#';


    /**
     * Standard folder name used by OpenSSH to hold key files
     */
    public static final String STD_KEYFILE_FOLDER_NAME = ".ssh";

    private static final long serialVersionUID = -585506072687602760L;

    private String keyType;
    private byte[] keyData;

    public PublicKeyEntry() {
        super();
    }

    public PublicKeyEntry(String keyType, byte... keyData) {
        this.keyType = keyType;
        this.keyData = keyData;
    }

    public String getKeyType() {
        return keyType;
    }

    public void setKeyType(String value) {
        this.keyType = value;
    }

    public byte[] getKeyData() {
        return keyData;
    }

    public void setKeyData(byte[] value) {
        this.keyData = value;
    }

    /**
     * @param fallbackResolver The {@link PublicKeyEntryResolver} to consult if
     * none of the built-in ones can be used. If {@code null} and no built-in
     * resolver can be used then an {@link InvalidKeySpecException} is thrown.
     * @return The resolved {@link PublicKey} - or {@code null} if could not be
     * resolved. <B>Note:</B> may be called only after key type and data bytes
     * have been set or exception(s) may be thrown
     * @throws IOException              If failed to decode the key
     * @throws GeneralSecurityException If failed to generate the key
     */
    public PublicKey resolvePublicKey(PublicKeyEntryResolver fallbackResolver) throws IOException, GeneralSecurityException {
        String kt = getKeyType();
        PublicKeyEntryResolver decoder = KeyUtils.getPublicKeyEntryDecoder(kt);
        if (decoder == null) {
            decoder = fallbackResolver;
        }
        if (decoder == null) {
            throw new InvalidKeySpecException("No decoder available for key type=" + kt);
        }

        return decoder.resolve(kt, getKeyData());
    }

    /**
     * @param sb The {@link Appendable} instance to encode the data into
     * @param fallbackResolver The {@link PublicKeyEntryResolver} to consult if
     * none of the built-in ones can be used. If {@code null} and no built-in
     * resolver can be used then an {@link InvalidKeySpecException} is thrown.
     * @return The {@link PublicKey} or {@code null} if could not resolve it
     * @throws IOException              If failed to decode/encode the key
     * @throws GeneralSecurityException If failed to generate the key
     * @see #resolvePublicKey(PublicKeyEntryResolver)
     */
    public PublicKey appendPublicKey(Appendable sb, PublicKeyEntryResolver fallbackResolver) throws IOException, GeneralSecurityException {
        PublicKey key = resolvePublicKey(fallbackResolver);
        if (key != null) {
            appendPublicKeyEntry(sb, key);
        }
        return key;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getKeyType()) + Arrays.hashCode(getKeyData());
    }

    /*
     * In case some derived class wants to define some "extended" equality
     * without having to repeat this code
     */
    protected boolean isEquivalent(PublicKeyEntry e) {
        if (this == e) {
            return true;
        }
        return Objects.equals(getKeyType(), e.getKeyType())
            && Arrays.equals(getKeyData(), e.getKeyData());
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
        return isEquivalent((PublicKeyEntry) obj);
    }

    @Override
    public String toString() {
        byte[] data = getKeyData();
        return getKeyType() + " " + (NumberUtils.isEmpty(data) ? "<no-key>" : Base64.encodeToString(data));
    }

    /**
     * @param data Assumed to contain at least {@code key-type base64-data} (anything
     *             beyond the BASE64 data is ignored) - ignored if {@code null}/empty
     * @return A {@link PublicKeyEntry} or {@code null} if no data
     * @throws IllegalArgumentException if bad format found
     * @see #parsePublicKeyEntry(PublicKeyEntry, String)
     */
    public static final PublicKeyEntry parsePublicKeyEntry(String data) throws IllegalArgumentException {
        if (GenericUtils.isEmpty(data)) {
            return null;
        } else {
            return parsePublicKeyEntry(new PublicKeyEntry(), data);
        }
    }

    /**
     * @param <E>   The generic entry type
     * @param entry The {@link PublicKeyEntry} whose contents are to be
     *              updated - ignored if {@code null}
     * @param data  Assumed to contain at least {@code key-type base64-data} (anything
     *              beyond the BASE64 data is ignored) - ignored if {@code null}/empty
     * @return The updated entry instance
     * @throws IllegalArgumentException if bad format found
     */
    public static final <E extends PublicKeyEntry> E parsePublicKeyEntry(E entry, String data) throws IllegalArgumentException {
        if (GenericUtils.isEmpty(data) || (entry == null)) {
            return entry;
        }

        int startPos = data.indexOf(' ');
        if (startPos <= 0) {
            throw new IllegalArgumentException("Bad format (no key data delimiter): " + data);
        }

        int endPos = data.indexOf(' ', startPos + 1);
        if (endPos <= startPos) {   // OK if no continuation beyond the BASE64 encoded data
            endPos = data.length();
        }

        String keyType = data.substring(0, startPos);
        String b64Data = data.substring(startPos + 1, endPos).trim();
        byte[] keyData = Base64.decodeString(b64Data);
        if (NumberUtils.isEmpty(keyData)) {
            throw new IllegalArgumentException("Bad format (no BASE64 key data): " + data);
        }

        entry.setKeyType(keyType);
        entry.setKeyData(keyData);
        return entry;
    }

    /**
     * @param key The {@link PublicKey}
     * @return The {@code OpenSSH} encoded data
     * @throws IllegalArgumentException If failed to encode
     * @see #appendPublicKeyEntry(Appendable, PublicKey)
     */
    public static String toString(PublicKey key) throws IllegalArgumentException {
        try {
            return appendPublicKeyEntry(new StringBuilder(Byte.MAX_VALUE), key).toString();
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed (" + e.getClass().getSimpleName() + ") to encode: " + e.getMessage(), e);
        }
    }

    /**
     * Encodes a public key data the same way as the {@link #parsePublicKeyEntry(String)} expects it
     *
     * @param <A> The generic appendable class
     * @param sb  The {@link Appendable} instance to encode the data into
     * @param key The {@link PublicKey} - ignored if {@code null}
     * @return The updated appendable instance
     * @throws IOException If failed to append the data
     */
    public static <A extends Appendable> A appendPublicKeyEntry(A sb, PublicKey key) throws IOException {
        if (key == null) {
            return sb;
        }

        @SuppressWarnings("unchecked")
        PublicKeyEntryDecoder<PublicKey, ?> decoder =
            (PublicKeyEntryDecoder<PublicKey, ?>) KeyUtils.getPublicKeyEntryDecoder(key);
        if (decoder == null) {
            throw new StreamCorruptedException("Cannot retrieve decoder for key=" + key.getAlgorithm());
        }

        try (ByteArrayOutputStream s = new ByteArrayOutputStream(Byte.MAX_VALUE)) {
            String keyType = decoder.encodePublicKey(s, key);
            byte[] bytes = s.toByteArray();
            String b64Data = Base64.encodeToString(bytes);
            sb.append(keyType).append(' ').append(b64Data);
        }

        return sb;
    }

    private static final class LazyDefaultKeysFolderHolder {
        private static final Path PATH = IdentityUtils.getUserHomeFolder().resolve(STD_KEYFILE_FOLDER_NAME);
    }

    /**
     * @return The default OpenSSH folder used to hold key files - e.g.,
     * {@code known_hosts}, {@code authorized_keys}, etc.
     */
    @SuppressWarnings("synthetic-access")
    public static Path getDefaultKeysFolderPath() {
        return LazyDefaultKeysFolderHolder.PATH;
    }
}
