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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.TreeMap;

import org.apache.sshd.common.keyprovider.KeyTypeIndicator;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * <P>
 * Represents a {@link PublicKey} whose data is formatted according to the
 * <A HREF="http://en.wikibooks.org/wiki/OpenSSH">OpenSSH</A> format:
 * </P>
 *
 * <PRE>
 * &lt;key-type&gt; &lt;base64-encoded-public-key-data&gt;
 * </PRE>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PublicKeyEntry implements Serializable, KeyTypeIndicator {
    /**
     * Character used to denote a comment line in the keys file
     */
    public static final char COMMENT_CHAR = '#';

    /**
     * Standard folder name used by OpenSSH to hold key files
     */
    public static final String STD_KEYFILE_FOLDER_NAME = ".ssh";

    private static final long serialVersionUID = -585506072687602760L;

    private static final NavigableMap<String, PublicKeyEntryDataResolver> KEY_DATA_RESOLVERS
            = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    private String keyType;
    private byte[] keyData;
    private PublicKeyEntryDataResolver keyDataResolver = PublicKeyEntryDataResolver.DEFAULT;

    public PublicKeyEntry() {
        super();
    }

    public PublicKeyEntry(String keyType, byte... keyData) {
        this.keyType = keyType;
        this.keyData = keyData;
    }

    @Override
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

    public PublicKeyEntryDataResolver getKeyDataResolver() {
        return keyDataResolver;
    }

    public void setKeyDataResolver(PublicKeyEntryDataResolver keyDataResolver) {
        this.keyDataResolver = keyDataResolver;
    }

    /**
     * If a {@link PublicKeyEntryDataResolver} has been set, then uses it - otherwise uses the
     * {@link PublicKeyEntryDataResolver#DEFAULT default one}.
     *
     * @return The resolved instance
     */
    public PublicKeyEntryDataResolver resolvePublicKeyEntryDataResolver() {
        PublicKeyEntryDataResolver resolver = getKeyDataResolver();
        return (resolver == null) ? PublicKeyEntryDataResolver.DEFAULT : resolver;
    }

    /**
     * @param  session                  The {@link SessionContext} for invoking this load command - may be {@code null}
     *                                  if not invoked within a session context (e.g., offline tool or session unknown).
     * @param  headers                  Any headers that may have been available when data was read
     * @param  fallbackResolver         The {@link PublicKeyEntryResolver} to consult if none of the built-in ones can
     *                                  be used. If {@code null} and no built-in resolver can be used then an
     *                                  {@link InvalidKeySpecException} is thrown.
     * @return                          The resolved {@link PublicKey} - or {@code null} if could not be resolved.
     *                                  <B>Note:</B> may be called only after key type and data bytes have been set or
     *                                  exception(s) may be thrown
     * @throws IOException              If failed to decode the key
     * @throws GeneralSecurityException If failed to generate the key
     */
    public PublicKey resolvePublicKey(
            SessionContext session, Map<String, String> headers, PublicKeyEntryResolver fallbackResolver)
            throws IOException, GeneralSecurityException {
        String kt = getKeyType();
        PublicKeyEntryResolver decoder = KeyUtils.getPublicKeyEntryDecoder(kt);
        if (decoder == null) {
            decoder = fallbackResolver;
        }
        if (decoder == null) {
            throw new InvalidKeySpecException("No decoder available for key type=" + kt);
        }

        return decoder.resolve(session, kt, getKeyData(), headers);
    }

    /**
     * @param  session                  The {@link SessionContext} for invoking this command - may be {@code null} if
     *                                  not invoked within a session context (e.g., offline tool or session unknown).
     * @param  sb                       The {@link Appendable} instance to encode the data into
     * @param  fallbackResolver         The {@link PublicKeyEntryResolver} to consult if none of the built-in ones can
     *                                  be used. If {@code null} and no built-in resolver can be used then an
     *                                  {@link InvalidKeySpecException} is thrown.
     * @return                          The {@link PublicKey} or {@code null} if could not resolve it
     * @throws IOException              If failed to decode/encode the key
     * @throws GeneralSecurityException If failed to generate the key
     * @see                             #resolvePublicKey(SessionContext, Map, PublicKeyEntryResolver)
     */
    public PublicKey appendPublicKey(
            SessionContext session, Appendable sb, PublicKeyEntryResolver fallbackResolver)
            throws IOException, GeneralSecurityException {
        PublicKey key = resolvePublicKey(session, Collections.emptyMap(), fallbackResolver);
        if (key != null) {
            appendPublicKeyEntry(sb, key, resolvePublicKeyEntryDataResolver());
        }
        return key;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getKeyType()) + Arrays.hashCode(getKeyData());
    }

    /*
     * In case some derived class wants to define some "extended" equality without having to repeat this code
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
        PublicKeyEntryDataResolver resolver = resolvePublicKeyEntryDataResolver();
        String encData = resolver.encodeEntryKeyData(getKeyData());
        return getKeyType() + " " + (GenericUtils.isEmpty(encData) ? "<no-key>" : encData);
    }

    /**
     * @param  session                  The {@link SessionContext} for invoking this command - may be {@code null} if
     *                                  not invoked within a session context (e.g., offline tool or session unknown).
     * @param  entries                  The entries to convert - ignored if {@code null}/empty
     * @param  fallbackResolver         The {@link PublicKeyEntryResolver} to consult if none of the built-in ones can
     *                                  be used. If {@code null} and no built-in resolver can be used then an
     *                                  {@link InvalidKeySpecException} is thrown.
     * @return                          The {@link List} of all {@link PublicKey}-s that have been resolved
     * @throws IOException              If failed to decode the key data
     * @throws GeneralSecurityException If failed to generate the {@link PublicKey} from the decoded data
     * @see                             #resolvePublicKey(SessionContext, Map, PublicKeyEntryResolver)
     */
    public static List<PublicKey> resolvePublicKeyEntries(
            SessionContext session, Collection<? extends PublicKeyEntry> entries, PublicKeyEntryResolver fallbackResolver)
            throws IOException, GeneralSecurityException {
        int numEntries = GenericUtils.size(entries);
        if (numEntries <= 0) {
            return Collections.emptyList();
        }

        List<PublicKey> keys = new ArrayList<>(numEntries);
        for (PublicKeyEntry e : entries) {
            Map<String, String> headers = (e instanceof AuthorizedKeyEntry)
                    ? ((AuthorizedKeyEntry) e).getLoginOptions()
                    : Collections.emptyMap();
            PublicKey k = e.resolvePublicKey(session, headers, fallbackResolver);
            if (k != null) {
                keys.add(k);
            }
        }

        return keys;
    }

    /**
     * Registers a specialized decoder for the public key entry data bytes instead of the
     * {@link PublicKeyEntryDataResolver#DEFAULT default} one.
     *
     * @param keyType  The key-type value (case <U>insensitive</U>) that will trigger the usage of this decoder - e.g.,
     *                 &quot;ssh-rsa&quot;, &quot;pgp-sign-dss&quot;, etc.
     * @param resolver The decoder to use
     */
    public static void registerKeyDataEntryResolver(String keyType, PublicKeyEntryDataResolver resolver) {
        ValidateUtils.checkNotNullAndNotEmpty(keyType, "No key type provided");
        Objects.requireNonNull(resolver, "No resolver provided");

        synchronized (KEY_DATA_RESOLVERS) {
            KEY_DATA_RESOLVERS.put(keyType, resolver);
        }
    }

    /**
     * @param  keyType The key-type value (case <U>insensitive</U>) that may have been previously
     *                 {@link #registerKeyDataEntryResolver(String, PublicKeyEntryDataResolver) registered} - e.g.,
     *                 &quot;ssh-rsa&quot;, &quot;pgp-sign-dss&quot;, etc.
     * @return         The registered resolver instance - {@code null} if none was registered
     */
    public static PublicKeyEntryDataResolver getKeyDataEntryResolver(String keyType) {
        keyType = ValidateUtils.checkNotNullAndNotEmpty(keyType, "No key type provided");

        synchronized (KEY_DATA_RESOLVERS) {
            return KEY_DATA_RESOLVERS.get(keyType);
        }
    }

    /**
     * @param  keyType The key-type value (case <U>insensitive</U>) that may have been previously
     *                 {@link #registerKeyDataEntryResolver(String, PublicKeyEntryDataResolver) registered} - e.g.,
     *                 &quot;ssh-rsa&quot;, &quot;pgp-sign-dss&quot;, etc.
     * @return         The un-registered resolver instance - {@code null} if none was registered
     */
    public static PublicKeyEntryDataResolver unregisterKeyDataEntryResolver(String keyType) {
        keyType = ValidateUtils.checkNotNullAndNotEmpty(keyType, "No key type provided");

        synchronized (KEY_DATA_RESOLVERS) {
            return KEY_DATA_RESOLVERS.remove(keyType);
        }
    }

    /**
     * @param  keyType keyType The key-type value (case <U>insensitive</U>) whose data is to be resolved - e.g.,
     *                 &quot;ssh-rsa&quot;, &quot;pgp-sign-dss&quot;, etc.
     * @return         If a specific resolver has been previously
     *                 {@link #registerKeyDataEntryResolver(String, PublicKeyEntryDataResolver) registered} then uses
     *                 it, otherwise the {@link PublicKeyEntryDataResolver#DEFAULT default} one.
     */
    public static PublicKeyEntryDataResolver resolveKeyDataEntryResolver(String keyType) {
        keyType = ValidateUtils.checkNotNullAndNotEmpty(keyType, "No key type provided");

        PublicKeyEntryDataResolver resolver = getKeyDataEntryResolver(keyType);
        if (resolver != null) {
            return resolver; // debug breakpoint
        }

        return PublicKeyEntryDataResolver.DEFAULT;
    }

    /**
     * @return A snapshot of the currently registered specialized {@link PublicKeyEntryDataResolver}-s, where key=the
     *         key-type value (case <U>insensitive</U>) - e.g., &quot;ssh-rsa&quot;, &quot;pgp-sign-dss&quot;, etc.,
     *         value=the associated {@link PublicKeyEntryDataResolver} for the key type
     */
    public static NavigableMap<String, PublicKeyEntryDataResolver> getRegisteredKeyDataEntryResolvers() {
        NavigableMap<String, PublicKeyEntryDataResolver> decoders;
        synchronized (KEY_DATA_RESOLVERS) {
            if (KEY_DATA_RESOLVERS.isEmpty()) {
                return Collections.emptyNavigableMap();
            }

            decoders = new TreeMap<>(KEY_DATA_RESOLVERS.comparator());
            decoders.putAll(KEY_DATA_RESOLVERS);
        }

        return decoders;
    }

    /**
     * @param  encData                  Assumed to contain at least {@code key-type base64-data} (anything beyond the
     *                                  BASE64 data is ignored) - ignored if {@code null}/empty
     * @return                          A {@link PublicKeyEntry} or {@code null} if no data
     * @throws IllegalArgumentException if bad format found
     * @see                             #parsePublicKeyEntry(String, PublicKeyEntryDataResolver)
     */
    public static PublicKeyEntry parsePublicKeyEntry(String encData) throws IllegalArgumentException {
        return parsePublicKeyEntry(encData, (PublicKeyEntryDataResolver) null);
    }

    /**
     * @param  encData                  Assumed to contain at least {@code key-type base64-data} (anything beyond the
     *                                  BASE64 data is ignored) - ignored if {@code null}/empty
     * @param  decoder                  The {@link PublicKeyEntryDataResolver} to use in order to decode the key data
     *                                  string into its bytes - if {@code null} then one is automatically
     *                                  {@link #resolveKeyDataEntryResolver(String) resolved}
     * @return                          A {@link PublicKeyEntry} or {@code null} if no data
     * @throws IllegalArgumentException if bad format found
     * @see                             #parsePublicKeyEntry(PublicKeyEntry, String, PublicKeyEntryDataResolver)
     */
    public static PublicKeyEntry parsePublicKeyEntry(
            String encData, PublicKeyEntryDataResolver decoder)
            throws IllegalArgumentException {
        String data = GenericUtils.replaceWhitespaceAndTrim(encData);
        if (GenericUtils.isEmpty(data)) {
            return null;
        } else {
            return parsePublicKeyEntry(new PublicKeyEntry(), data, decoder);
        }
    }

    /**
     * @param  <E>                      The generic entry type
     * @param  entry                    The {@link PublicKeyEntry} whose contents are to be updated - ignored if
     *                                  {@code null}
     * @param  encData                  Assumed to contain at least {@code key-type base64-data} (anything beyond the
     *                                  BASE64 data is ignored) - ignored if {@code null}/empty
     * @return                          The updated entry instance
     * @throws IllegalArgumentException if bad format found
     * @see                             #parsePublicKeyEntry(PublicKeyEntry, String, PublicKeyEntryDataResolver)
     */
    public static <E extends PublicKeyEntry> E parsePublicKeyEntry(E entry, String encData)
            throws IllegalArgumentException {
        return parsePublicKeyEntry(entry, encData, null);
    }

    /**
     * @param  <E>                      The generic entry type
     * @param  entry                    The {@link PublicKeyEntry} whose contents are to be updated - ignored if
     *                                  {@code null}
     * @param  encData                  Assumed to contain at least {@code key-type base64-data} (anything beyond the
     *                                  BASE64 data is ignored) - ignored if {@code null}/empty
     * @param  decoder                  The {@link PublicKeyEntryDataResolver} to use in order to decode the key data
     *                                  string into its bytes - if {@code null} then one is automatically
     *                                  {@link #resolveKeyDataEntryResolver(String) resolved}
     * @return                          The updated entry instance
     * @throws IllegalArgumentException if bad format found
     */
    public static <E extends PublicKeyEntry> E parsePublicKeyEntry(
            E entry, String encData, PublicKeyEntryDataResolver decoder)
            throws IllegalArgumentException {
        String data = GenericUtils.replaceWhitespaceAndTrim(encData);
        if (GenericUtils.isEmpty(data) || (entry == null)) {
            return entry;
        }

        int startPos = data.indexOf(' ');
        if (startPos <= 0) {
            throw new IllegalArgumentException("Bad format (no key data delimiter): " + data);
        }

        int endPos = data.indexOf(' ', startPos + 1);
        if (endPos <= startPos) { // OK if no continuation beyond the encoded key data
            endPos = data.length();
        }

        String keyType = data.substring(0, startPos);
        if (decoder == null) {
            decoder = resolveKeyDataEntryResolver(keyType);
        }
        String b64Data = data.substring(startPos + 1, endPos).trim();
        byte[] keyData = decoder.decodeEntryKeyData(b64Data);
        if (NumberUtils.isEmpty(keyData)) {
            throw new IllegalArgumentException("Bad format (no BASE64 key data): " + data);
        }

        entry.setKeyType(keyType);
        entry.setKeyDataResolver(decoder);
        entry.setKeyData(keyData);
        return entry;
    }

    /**
     * @param  key                      The {@link PublicKey}
     * @return                          The {@code OpenSSH} encoded data
     * @throws IllegalArgumentException If failed to encode
     * @see                             #toString(PublicKey, PublicKeyEntryDataResolver)
     */
    public static String toString(PublicKey key) throws IllegalArgumentException {
        return toString(key, null);
    }

    /**
     * @param  key                      The {@link PublicKey}
     * @param  encoder                  The {@link PublicKeyEntryDataResolver} to use in order to encode the key data
     *                                  bytes into a string representation - if {@code null} then one is automatically
     *                                  {@link #resolveKeyDataEntryResolver(String) resolved}
     * @return                          The {@code OpenSSH} encoded data
     * @throws IllegalArgumentException If failed to encode
     * @see                             #appendPublicKeyEntry(Appendable, PublicKey, PublicKeyEntryDataResolver)
     */
    public static String toString(
            PublicKey key, PublicKeyEntryDataResolver encoder)
            throws IllegalArgumentException {
        try {
            return appendPublicKeyEntry(new StringBuilder(Byte.MAX_VALUE), key, encoder).toString();
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed (" + e.getClass().getSimpleName() + ") to encode: " + e.getMessage(), e);
        }
    }

    /**
     * Encodes a public key data the same way as the {@link #parsePublicKeyEntry(String)} expects it
     *
     * @param  <A>         The generic appendable class
     * @param  sb          The {@link Appendable} instance to encode the data into
     * @param  key         The {@link PublicKey} - ignored if {@code null}
     * @return             The updated appendable instance
     * @throws IOException If failed to append the data
     * @see                #appendPublicKeyEntry(Appendable, PublicKey, PublicKeyEntryDataResolver)
     */
    public static <A extends Appendable> A appendPublicKeyEntry(A sb, PublicKey key) throws IOException {
        return appendPublicKeyEntry(sb, key, null);
    }

    /**
     * @param  <A>         The generic appendable class
     * @param  sb          The {@link Appendable} instance to encode the data into
     * @param  key         The {@link PublicKey} - ignored if {@code null}
     * @param  encoder     The {@link PublicKeyEntryDataResolver} to use in order to encode the key data bytes into a
     *                     string representation - if {@code null} then one is automatically
     *                     {@link #resolveKeyDataEntryResolver(String) resolved}
     * @return             The updated appendable instance
     * @throws IOException If failed to append the data
     */
    public static <A extends Appendable> A appendPublicKeyEntry(
            A sb, PublicKey key, PublicKeyEntryDataResolver encoder)
            throws IOException {
        if (key == null) {
            return sb;
        }

        @SuppressWarnings("unchecked")
        PublicKeyEntryDecoder<PublicKey, ?> decoder
                = (PublicKeyEntryDecoder<PublicKey, ?>) KeyUtils.getPublicKeyEntryDecoder(key);
        if (decoder == null) {
            throw new StreamCorruptedException("Cannot retrieve decoder for key=" + key.getAlgorithm());
        }

        try (ByteArrayOutputStream s = new ByteArrayOutputStream(Byte.MAX_VALUE)) {
            String keyType = decoder.encodePublicKey(s, key);
            byte[] bytes = s.toByteArray();
            if (encoder == null) {
                encoder = resolveKeyDataEntryResolver(keyType);
            }

            String encData = encoder.encodeEntryKeyData(bytes);
            sb.append(keyType).append(' ').append(encData);
        }

        return sb;
    }

    private static final class LazyDefaultKeysFolderHolder {
        private static final Path PATH = IdentityUtils.getUserHomeFolder().resolve(STD_KEYFILE_FOLDER_NAME);

        private LazyDefaultKeysFolderHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    /**
     * @return The default OpenSSH folder used to hold key files - e.g., {@code known_hosts}, {@code authorized_keys},
     *         etc.
     */
    @SuppressWarnings("synthetic-access")
    public static Path getDefaultKeysFolderPath() {
        return LazyDefaultKeysFolderHolder.PATH;
    }
}
