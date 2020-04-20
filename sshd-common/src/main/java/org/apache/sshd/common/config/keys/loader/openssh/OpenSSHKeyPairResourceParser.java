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

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.net.ProtocolException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

import javax.security.auth.login.FailedLoginException;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProvider.ResourceDecodeResult;
import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PrivateKeyEntryDecoder;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.config.keys.loader.AbstractKeyPairResourceParser;
import org.apache.sshd.common.config.keys.loader.openssh.kdf.BCryptKdfOptions;
import org.apache.sshd.common.config.keys.loader.openssh.kdf.RawKdfOptions;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Basic support for <A HREF=
 * "http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key?rev=1.1&content-type=text/x-cvsweb-markup">OpenSSH
 * key file(s)</A>
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class OpenSSHKeyPairResourceParser extends AbstractKeyPairResourceParser {
    public static final String BEGIN_MARKER = "BEGIN OPENSSH PRIVATE KEY";
    public static final List<String> BEGINNERS = Collections.unmodifiableList(Collections.singletonList(BEGIN_MARKER));

    public static final String END_MARKER = "END OPENSSH PRIVATE KEY";
    public static final List<String> ENDERS = Collections.unmodifiableList(Collections.singletonList(END_MARKER));

    public static final String AUTH_MAGIC = "openssh-key-v1";
    public static final OpenSSHKeyPairResourceParser INSTANCE = new OpenSSHKeyPairResourceParser();

    private static final byte[] AUTH_MAGIC_BYTES = AUTH_MAGIC.getBytes(StandardCharsets.UTF_8);
    private static final Map<String, PrivateKeyEntryDecoder<?, ?>> BY_KEY_TYPE_DECODERS_MAP
            = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    private static final Map<Class<?>, PrivateKeyEntryDecoder<?, ?>> BY_KEY_CLASS_DECODERS_MAP = new HashMap<>();

    static {
        registerPrivateKeyEntryDecoder(OpenSSHRSAPrivateKeyDecoder.INSTANCE);
        registerPrivateKeyEntryDecoder(OpenSSHDSSPrivateKeyEntryDecoder.INSTANCE);

        if (SecurityUtils.isECCSupported()) {
            registerPrivateKeyEntryDecoder(OpenSSHECDSAPrivateKeyEntryDecoder.INSTANCE);
        }
        if (SecurityUtils.isEDDSACurveSupported()) {
            registerPrivateKeyEntryDecoder(SecurityUtils.getOpenSSHEDDSAPrivateKeyEntryDecoder());
        }
    }

    public OpenSSHKeyPairResourceParser() {
        super(BEGINNERS, ENDERS);
    }

    @Override
    public Collection<KeyPair> extractKeyPairs(
            SessionContext session, NamedResource resourceKey,
            String beginMarker, String endMarker,
            FilePasswordProvider passwordProvider,
            InputStream stream, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        boolean debugEnabled = log.isDebugEnabled();

        stream = validateStreamMagicMarker(session, resourceKey, stream);

        String cipher = KeyEntryResolver.decodeString(stream, MAX_CIPHER_NAME_LENGTH);
        OpenSSHKdfOptions kdfOptions = resolveKdfOptions(session, resourceKey, beginMarker, endMarker, stream, headers);
        OpenSSHParserContext context = new OpenSSHParserContext(cipher, kdfOptions);
        int numKeys = KeyEntryResolver.decodeInt(stream);
        if (numKeys <= 0) {
            if (debugEnabled) {
                log.debug("extractKeyPairs({}) no encoded keys for context={}", resourceKey, context);
            }
            return Collections.emptyList();
        }

        if (debugEnabled) {
            log.debug("extractKeyPairs({}) decode {} keys using context={}", resourceKey, numKeys, context);
        }

        List<PublicKey> publicKeys = new ArrayList<>(numKeys);
        boolean traceEnabled = log.isTraceEnabled();
        for (int index = 1; index <= numKeys; index++) {
            PublicKey pubKey = readPublicKey(session, resourceKey, context, stream, headers);
            ValidateUtils.checkNotNull(pubKey, "Empty public key #%d in %s", index, resourceKey);
            if (traceEnabled) {
                log.trace("extractKeyPairs({}) read public key #{}: {} {}",
                        resourceKey, index, KeyUtils.getKeyType(pubKey), KeyUtils.getFingerPrint(pubKey));
            }
            publicKeys.add(pubKey);
        }

        byte[] privateData = KeyEntryResolver.readRLEBytes(stream, MAX_PRIVATE_KEY_DATA_SIZE);
        try {
            if (!context.isEncrypted()) {
                try (InputStream bais = new ByteArrayInputStream(privateData)) {
                    return readPrivateKeys(session, resourceKey, context, publicKeys, passwordProvider, bais);
                }
            }

            if (passwordProvider == null) {
                throw new FailedLoginException("No password provider for encrypted key in " + resourceKey);
            }

            for (int retryCount = 0;; retryCount++) {
                String pwd = passwordProvider.getPassword(session, resourceKey, retryCount);
                if (GenericUtils.isEmpty(pwd)) {
                    return Collections.emptyList();
                }

                List<KeyPair> keys;
                try {
                    byte[] decryptedData = kdfOptions.decodePrivateKeyBytes(
                            session, resourceKey, context.getCipherName(), privateData, pwd);
                    try (InputStream bais = new ByteArrayInputStream(decryptedData)) {
                        keys = readPrivateKeys(session, resourceKey, context, publicKeys, passwordProvider, bais);
                    } finally {
                        Arrays.fill(decryptedData, (byte) 0); // get rid of sensitive data a.s.a.p.
                    }
                } catch (IOException | GeneralSecurityException | RuntimeException e) {
                    ResourceDecodeResult result
                            = passwordProvider.handleDecodeAttemptResult(session, resourceKey, retryCount, pwd, e);
                    pwd = null; // get rid of sensitive data a.s.a.p.
                    if (result == null) {
                        result = ResourceDecodeResult.TERMINATE;
                    }

                    switch (result) {
                        case TERMINATE:
                            throw e;
                        case RETRY:
                            continue;
                        case IGNORE:
                            return Collections.emptyList();
                        default:
                            throw new ProtocolException(
                                    "Unsupported decode attempt result (" + result + ") for " + resourceKey);
                    }
                }

                passwordProvider.handleDecodeAttemptResult(session, resourceKey, retryCount, pwd, null);
                pwd = null; // get rid of sensitive data a.s.a.p.
                return keys;
            }
        } finally {
            Arrays.fill(privateData, (byte) 0); // get rid of sensitive data a.s.a.p.
        }
    }

    protected OpenSSHKdfOptions resolveKdfOptions(
            SessionContext session, NamedResource resourceKey,
            String beginMarker, String endMarker, InputStream stream, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        String kdfName = KeyEntryResolver.decodeString(stream, OpenSSHKdfOptions.MAX_KDF_NAME_LENGTH);
        byte[] kdfOptions = KeyEntryResolver.readRLEBytes(stream, OpenSSHKdfOptions.MAX_KDF_OPTIONS_SIZE);
        OpenSSHKdfOptions options;
        // TODO define a factory class where users can register extra KDF options
        if (BCryptKdfOptions.NAME.equalsIgnoreCase(kdfName)) {
            options = new BCryptKdfOptions();
        } else {
            options = new RawKdfOptions();
        }

        options.initialize(kdfName, kdfOptions);
        return options;
    }

    protected PublicKey readPublicKey(
            SessionContext session, NamedResource resourceKey,
            OpenSSHParserContext context,
            InputStream stream, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        byte[] keyData = KeyEntryResolver.readRLEBytes(stream, MAX_PUBLIC_KEY_DATA_SIZE);
        try (InputStream bais = new ByteArrayInputStream(keyData)) {
            String keyType = KeyEntryResolver.decodeString(bais, MAX_KEY_TYPE_NAME_LENGTH);
            PublicKeyEntryDecoder<?, ?> decoder = KeyUtils.getPublicKeyEntryDecoder(keyType);
            if (decoder == null) {
                throw new NoSuchAlgorithmException("Unsupported key type (" + keyType + ") in " + resourceKey);
            }

            return decoder.decodePublicKey(session, keyType, bais, headers);
        }
    }

    /*
     * NOTE: called AFTER decrypting the original bytes, however we still propagate the password provider - just in case
     * some "sub-encryption" is detected
     */
    protected List<KeyPair> readPrivateKeys(
            SessionContext session, NamedResource resourceKey,
            OpenSSHParserContext context, Collection<? extends PublicKey> publicKeys,
            FilePasswordProvider passwordProvider, InputStream stream)
            throws IOException, GeneralSecurityException {
        if (GenericUtils.isEmpty(publicKeys)) {
            return Collections.emptyList();
        }

        boolean traceEnabled = log.isTraceEnabled();
        int check1 = KeyEntryResolver.decodeInt(stream);
        int check2 = KeyEntryResolver.decodeInt(stream);
        if (traceEnabled) {
            log.trace("readPrivateKeys({}) check1=0x{}, check2=0x{}",
                    resourceKey, Integer.toHexString(check1), Integer.toHexString(check2));
        }

        /*
         * According to the documentation:
         *
         * Before the key is encrypted, a random integer is assigned to both checkint fields so successful decryption
         * can be quickly checked by verifying that both checkint fields hold the same value.
         */
        if (check1 != check2) {
            throw new StreamCorruptedException(
                    "Mismatched private key check values ("
                                               + Integer.toHexString(check1) + "/" + Integer.toHexString(check2) + ") in "
                                               + resourceKey);
        }

        List<KeyPair> keyPairs = new ArrayList<>(publicKeys.size());
        for (PublicKey pubKey : publicKeys) {
            String pubType = KeyUtils.getKeyType(pubKey);
            int keyIndex = keyPairs.size() + 1;
            if (traceEnabled) {
                log.trace("extractKeyPairs({}) read private key #{}: {}",
                        resourceKey, keyIndex, pubType);
            }

            Map.Entry<PrivateKey, String> prvData
                    = readPrivateKey(session, resourceKey, context, pubType, passwordProvider, stream);
            PrivateKey prvKey = (prvData == null) ? null : prvData.getKey();
            ValidateUtils.checkNotNull(prvKey, "Empty private key #%d in %s", keyIndex, resourceKey);

            String prvType = KeyUtils.getKeyType(prvKey);
            ValidateUtils.checkTrue(Objects.equals(pubType, prvType),
                    "Mismatched public (%s) vs. private (%s) key type #%d in %s",
                    pubType, prvType, keyIndex, resourceKey);

            if (traceEnabled) {
                log.trace("extractKeyPairs({}) add private key #{}: {} {}",
                        resourceKey, keyIndex, prvType, prvData.getValue());
            }
            keyPairs.add(new KeyPair(pubKey, prvKey));
        }

        return keyPairs;
    }

    protected Map.Entry<PrivateKey, String> readPrivateKey(
            SessionContext session, NamedResource resourceKey,
            OpenSSHParserContext context, String keyType,
            FilePasswordProvider passwordProvider, InputStream stream)
            throws IOException, GeneralSecurityException {
        String prvType = KeyEntryResolver.decodeString(stream, MAX_KEY_TYPE_NAME_LENGTH);
        if (!Objects.equals(keyType, prvType)) {
            throw new StreamCorruptedException(
                    "Mismatched private key type: "
                                               + ", expected=" + keyType + ", actual=" + prvType
                                               + " in " + resourceKey);
        }

        PrivateKeyEntryDecoder<?, ?> decoder = getPrivateKeyEntryDecoder(prvType);
        if (decoder == null) {
            throw new NoSuchAlgorithmException("Unsupported key type (" + prvType + ") in " + resourceKey);
        }

        PrivateKey prvKey = decoder.decodePrivateKey(session, prvType, passwordProvider, stream);
        if (prvKey == null) {
            throw new InvalidKeyException("Cannot parse key type (" + prvType + ") in " + resourceKey);
        }

        String comment = KeyEntryResolver.decodeString(stream, MAX_KEY_COMMENT_LENGTH);
        return new SimpleImmutableEntry<>(prvKey, comment);
    }

    protected <S extends InputStream> S validateStreamMagicMarker(
            SessionContext session, NamedResource resourceKey, S stream)
            throws IOException {
        byte[] actual = new byte[AUTH_MAGIC_BYTES.length];
        IoUtils.readFully(stream, actual);
        if (!Arrays.equals(AUTH_MAGIC_BYTES, actual)) {
            throw new StreamCorruptedException(
                    resourceKey + ": Mismatched magic marker value: " + BufferUtils.toHex(':', actual));
        }

        int eos = stream.read();
        if (eos == -1) {
            throw new EOFException(resourceKey + ": Premature EOF after magic marker value");
        }

        if (eos != 0) {
            throw new StreamCorruptedException(
                    resourceKey + ": Missing EOS after magic marker value: 0x" + Integer.toHexString(eos));
        }

        return stream;
    }

    /**
     * @param  decoder                  The decoder to register
     * @throws IllegalArgumentException if no decoder or not key type or no supported names for the decoder
     * @see                             PrivateKeyEntryDecoder#getPublicKeyType()
     * @see                             PrivateKeyEntryDecoder#getSupportedKeyTypes()
     */
    public static void registerPrivateKeyEntryDecoder(PrivateKeyEntryDecoder<?, ?> decoder) {
        Objects.requireNonNull(decoder, "No decoder specified");

        Class<?> pubType = Objects.requireNonNull(decoder.getPublicKeyType(), "No public key type declared");
        Class<?> prvType = Objects.requireNonNull(decoder.getPrivateKeyType(), "No private key type declared");
        synchronized (BY_KEY_CLASS_DECODERS_MAP) {
            BY_KEY_CLASS_DECODERS_MAP.put(pubType, decoder);
            BY_KEY_CLASS_DECODERS_MAP.put(prvType, decoder);
        }

        Collection<String> names
                = ValidateUtils.checkNotNullAndNotEmpty(decoder.getSupportedKeyTypes(), "No supported key type");
        synchronized (BY_KEY_TYPE_DECODERS_MAP) {
            for (String n : names) {
                PrivateKeyEntryDecoder<?, ?> prev = BY_KEY_TYPE_DECODERS_MAP.put(n, decoder);
                if (prev != null) {
                    // noinspection UnnecessaryContinue
                    continue; // debug breakpoint
                }
            }
        }
    }

    /**
     * @param  keyType The {@code OpenSSH} key type string - e.g., {@code ssh-rsa, ssh-dss} - ignored if
     *                 {@code null}/empty
     * @return         The registered {@link PrivateKeyEntryDecoder} or {code null} if not found
     */
    public static PrivateKeyEntryDecoder<?, ?> getPrivateKeyEntryDecoder(String keyType) {
        if (GenericUtils.isEmpty(keyType)) {
            return null;
        }

        synchronized (BY_KEY_TYPE_DECODERS_MAP) {
            return BY_KEY_TYPE_DECODERS_MAP.get(keyType);
        }
    }

    /**
     * @param  kp The {@link KeyPair} to examine - ignored if {@code null}
     * @return    The matching {@link PrivateKeyEntryDecoder} provided <U>both</U> the public and private keys have the
     *            same decoder - {@code null} if no match found
     * @see       #getPrivateKeyEntryDecoder(Key)
     */
    public static PrivateKeyEntryDecoder<?, ?> getPrivateKeyEntryDecoder(KeyPair kp) {
        if (kp == null) {
            return null;
        }

        PrivateKeyEntryDecoder<?, ?> d1 = getPrivateKeyEntryDecoder(kp.getPublic());
        PrivateKeyEntryDecoder<?, ?> d2 = getPrivateKeyEntryDecoder(kp.getPrivate());
        if (d1 == d2) {
            return d1;
        } else {
            return null; // some kind of mixed keys...
        }
    }

    /**
     * @param  key The {@link Key} (public or private) - ignored if {@code null}
     * @return     The registered {@link PrivateKeyEntryDecoder} for this key or {code null} if no match found
     * @see        #getPrivateKeyEntryDecoder(Class)
     */
    public static PrivateKeyEntryDecoder<?, ?> getPrivateKeyEntryDecoder(Key key) {
        if (key == null) {
            return null;
        } else {
            return getPrivateKeyEntryDecoder(key.getClass());
        }
    }

    /**
     * @param  keyType The key {@link Class} - ignored if {@code null} or not a {@link Key} compatible type
     * @return         The registered {@link PrivateKeyEntryDecoder} or {code null} if no match found
     */
    public static PrivateKeyEntryDecoder<?, ?> getPrivateKeyEntryDecoder(Class<?> keyType) {
        if ((keyType == null) || (!Key.class.isAssignableFrom(keyType))) {
            return null;
        }

        synchronized (BY_KEY_TYPE_DECODERS_MAP) {
            PrivateKeyEntryDecoder<?, ?> decoder = BY_KEY_CLASS_DECODERS_MAP.get(keyType);
            if (decoder != null) {
                return decoder;
            }

            // in case it is a derived class
            for (PrivateKeyEntryDecoder<?, ?> dec : BY_KEY_CLASS_DECODERS_MAP.values()) {
                Class<?> pubType = dec.getPublicKeyType();
                Class<?> prvType = dec.getPrivateKeyType();
                if (pubType.isAssignableFrom(keyType) || prvType.isAssignableFrom(keyType)) {
                    return dec;
                }
            }
        }

        return null;
    }
}
