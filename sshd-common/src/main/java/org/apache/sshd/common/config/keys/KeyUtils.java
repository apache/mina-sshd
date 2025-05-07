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

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.impl.DSSPublicKeyEntryDecoder;
import org.apache.sshd.common.config.keys.impl.ECDSAPublicKeyEntryDecoder;
import org.apache.sshd.common.config.keys.impl.OpenSSHCertificateDecoder;
import org.apache.sshd.common.config.keys.impl.RSAPublicKeyDecoder;
import org.apache.sshd.common.config.keys.impl.SkECDSAPublicKeyEntryDecoder;
import org.apache.sshd.common.config.keys.impl.SkED25519PublicKeyEntryDecoder;
import org.apache.sshd.common.config.keys.u2f.SkED25519PublicKey;
import org.apache.sshd.common.config.keys.u2f.SkEcdsaPublicKey;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.digest.DigestFactory;
import org.apache.sshd.common.digest.DigestUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils.MapBuilder;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Utility class for keys
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class KeyUtils {
    /**
     * Name of algorithm for RSA keys to be used when calling security provider
     */
    public static final String RSA_ALGORITHM = "RSA";

    /**
     * The most commonly used RSA public key exponent
     */
    public static final BigInteger DEFAULT_RSA_PUBLIC_EXPONENT = BigInteger.valueOf(65537);

    /**
     * Name of algorithm for DSS keys to be used when calling security provider
     */
    public static final String DSS_ALGORITHM = "DSA";

    /**
     * Name of algorithm for EC keys to be used when calling security provider
     */
    public static final String EC_ALGORITHM = "EC";

    /**
     * The {@link Set} of {@link PosixFilePermission} <U>not</U> allowed if strict permissions are enforced on key files
     */
    public static final Set<PosixFilePermission> STRICTLY_PROHIBITED_FILE_PERMISSION = Collections.unmodifiableSet(
            EnumSet.of(
                    PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_EXECUTE,
                    PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE));

    /**
     * System property that can be used to control the default fingerprint factory used for keys. If not set the
     * {@link #DEFAULT_FINGERPRINT_DIGEST_FACTORY} is used
     */
    public static final String KEY_FINGERPRINT_FACTORY_PROP = "org.apache.sshd.keyFingerprintFactory";

    /**
     * The default {@link Factory} of {@link Digest}s initialized as the value of
     * {@link #getDefaultFingerPrintFactory()} if not overridden by {@link #KEY_FINGERPRINT_FACTORY_PROP} or
     * {@link #setDefaultFingerPrintFactory(DigestFactory)}
     */
    public static final DigestFactory DEFAULT_FINGERPRINT_DIGEST_FACTORY = BuiltinDigests.sha256;

    /** @see <A HREF="">https://tools.ietf.org/html/rfc8332#section-3</A> */
    public static final String RSA_SHA256_KEY_TYPE_ALIAS = "rsa-sha2-256";
    public static final String RSA_SHA512_KEY_TYPE_ALIAS = "rsa-sha2-512";
    public static final String RSA_SHA256_CERT_TYPE_ALIAS = "rsa-sha2-256-cert-v01@openssh.com";
    public static final String RSA_SHA512_CERT_TYPE_ALIAS = "rsa-sha2-512-cert-v01@openssh.com";

    private static final AtomicReference<DigestFactory> DEFAULT_DIGEST_HOLDER = new AtomicReference<>();

    private static final Map<String, PublicKeyEntryDecoder<?, ?>> BY_KEY_TYPE_DECODERS_MAP
            = new ConcurrentHashMap<>();

    private static final Map<String, String> KEY_TYPE_ALIASES
            = MapBuilder.<String, String> builder()
                    .put(RSA_SHA256_KEY_TYPE_ALIAS, KeyPairProvider.SSH_RSA)
                    .put(RSA_SHA512_KEY_TYPE_ALIAS, KeyPairProvider.SSH_RSA)
                    .put(RSA_SHA256_CERT_TYPE_ALIAS, KeyPairProvider.SSH_RSA_CERT)
                    .put(RSA_SHA512_CERT_TYPE_ALIAS, KeyPairProvider.SSH_RSA_CERT)
                    .immutable();

    private static final Map<String, String> SIGNATURE_ALGORITHM_MAP
            = MapBuilder.<String, String> builder()
                    .put(RSA_SHA256_CERT_TYPE_ALIAS, RSA_SHA256_KEY_TYPE_ALIAS)
                    .put(RSA_SHA512_CERT_TYPE_ALIAS, RSA_SHA512_KEY_TYPE_ALIAS)
                    .put(KeyPairProvider.SSH_RSA_CERT, KeyPairProvider.SSH_RSA)
                    .put(KeyPairProvider.SSH_DSS_CERT, KeyPairProvider.SSH_DSS)
                    .put(KeyPairProvider.SSH_ED25519_CERT, KeyPairProvider.SSH_ED25519)
                    .put(KeyPairProvider.SSH_ECDSA_SHA2_NISTP256_CERT, KeyPairProvider.ECDSA_SHA2_NISTP256)
                    .put(KeyPairProvider.SSH_ECDSA_SHA2_NISTP384_CERT, KeyPairProvider.ECDSA_SHA2_NISTP384)
                    .put(KeyPairProvider.SSH_ECDSA_SHA2_NISTP521_CERT, KeyPairProvider.ECDSA_SHA2_NISTP521)
                    .immutable();

    static {

        registerPublicKeyEntryDecoder(OpenSSHCertificateDecoder.INSTANCE);
        registerPublicKeyEntryDecoder(RSAPublicKeyDecoder.INSTANCE);
        registerPublicKeyEntryDecoder(DSSPublicKeyEntryDecoder.INSTANCE);

        registerPublicKeyEntryDecoder(ECDSAPublicKeyEntryDecoder.INSTANCE);

        if (SecurityUtils.isEDDSACurveSupported()) {
            registerPublicKeyEntryDecoder(SecurityUtils.getEDDSAPublicKeyEntryDecoder());
        }

        registerPublicKeyEntryDecoder(SkECDSAPublicKeyEntryDecoder.INSTANCE);

        if (SecurityUtils.isEDDSACurveSupported()) {
            registerPublicKeyEntryDecoder(SkED25519PublicKeyEntryDecoder.INSTANCE);
        }

    }

    private KeyUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * <P>
     * Checks if a path has strict permissions
     * </P>
     * <UL>
     * <LI>
     * <P>
     * The path may not have {@link PosixFilePermission#OTHERS_EXECUTE} permission
     * </P>
     * </LI>
     *
     * <LI>
     * <P>
     * (For {@code Unix}) The path may not have group or others permissions
     * </P>
     * </LI>
     *
     * <LI>
     * <P>
     * (For {@code Unix}) If the path is a file, then its folder may not have group or others permissions
     * </P>
     * </LI>
     *
     * <LI>
     * <P>
     * The path must be owned by current user.
     * </P>
     * </LI>
     *
     * <LI>
     * <P>
     * (For {@code Unix}) The path may be owned by root.
     * </P>
     * </LI>
     *
     * <LI>
     * <P>
     * (For {@code Unix}) If the path is a file, then its folder must also have valid owner.
     * </P>
     * </LI>
     *
     * </UL>
     *
     * @param  path        The {@link Path} to be checked - ignored if {@code null} or does not exist
     * @param  options     The {@link LinkOption}s to use to query the file's permissions
     * @return             The violated permission as {@link SimpleImmutableEntry} where key is a message and value is
     *                     the offending object {@link PosixFilePermission} or {@link String} for owner - {@code null}
     *                     if no violations detected
     * @throws IOException If failed to retrieve the permissions
     * @see                #STRICTLY_PROHIBITED_FILE_PERMISSION
     */
    public static SimpleImmutableEntry<String, Object> validateStrictKeyFilePermissions(Path path, LinkOption... options)
            throws IOException {
        if ((path == null) || (!Files.exists(path, options))) {
            return null;
        }

        /*
         * Android permission are not really consistent with standard Linux ones since the device is
         * a "single" user O/S but with each application being a different "user". We therefore assume
         * that if the application has access to a file, then it is good enough since there is really
         * only one user, and we don't have to worry about multi-user access. Furthermore, the SE Linux
         * security available on Android seems to be enough of a safeguard against inadvertent or even
         * malicious access.
         */
        if (OsUtils.isAndroid()) {
            return null;
        }

        Collection<PosixFilePermission> perms = IoUtils.getPermissions(path, options);
        if (GenericUtils.isEmpty(perms)) {
            return null;
        }

        if (perms.contains(PosixFilePermission.OTHERS_EXECUTE)) {
            PosixFilePermission p = PosixFilePermission.OTHERS_EXECUTE;
            return new SimpleImmutableEntry<>(String.format("Permissions violation (%s)", p), p);
        }

        if (OsUtils.isUNIX()) {
            PosixFilePermission p = IoUtils.validateExcludedPermissions(perms, STRICTLY_PROHIBITED_FILE_PERMISSION);
            if (p != null) {
                return new SimpleImmutableEntry<>(String.format("Permissions violation (%s)", p), p);
            }

            if (Files.isRegularFile(path, options)) {
                Path parent = path.getParent();
                p = IoUtils.validateExcludedPermissions(IoUtils.getPermissions(parent, options),
                        STRICTLY_PROHIBITED_FILE_PERMISSION);
                if (p != null) {
                    return new SimpleImmutableEntry<>(String.format("Parent permissions violation (%s)", p), p);
                }
            }
        }

        String owner = IoUtils.getFileOwner(path, options);
        if (GenericUtils.isEmpty(owner)) {
            // we cannot get owner
            // general issue: jvm does not support permissions
            // security issue: specific filesystem does not support permissions
            return null;
        }

        String current = OsUtils.getCurrentUser();
        Set<String> expected = new HashSet<>();
        expected.add(current);
        if (OsUtils.isUNIX()) {
            // Windows "Administrator" was considered however in Windows most likely a group is used.
            expected.add(OsUtils.ROOT_USER);
        }

        if (!expected.contains(owner)) {
            return new SimpleImmutableEntry<>(String.format("Owner violation (%s)", owner), owner);
        }

        if (OsUtils.isUNIX()) {
            if (Files.isRegularFile(path, options)) {
                String parentOwner = IoUtils.getFileOwner(path.getParent(), options);
                if ((!GenericUtils.isEmpty(parentOwner)) && (!expected.contains(parentOwner))) {
                    return new SimpleImmutableEntry<>(String.format("Parent owner violation (%s)", parentOwner), parentOwner);
                }
            }
        }

        return null;
    }

    /**
     * Reads a single {@link PublicKey} from a public key file.
     *
     * @param  path                     {@link Path} of the file to read; must not be {@code null}
     * @return                          the {@link PublicKey}, may be {@code null} if the file is empty
     * @throws IOException              if the file cannot be read or parsed
     * @throws GeneralSecurityException if the file contents cannot be read as a single {@link PublicKey}
     */
    public static PublicKey loadPublicKey(Path path) throws IOException, GeneralSecurityException {
        List<AuthorizedKeyEntry> keys = AuthorizedKeyEntry.readAuthorizedKeys(Objects.requireNonNull(path));
        if (GenericUtils.isEmpty(keys)) {
            return null;
        }
        if (keys.size() > 1) {
            throw new InvalidKeySpecException("Public key file contains multiple entries: " + path);
        }
        return keys.get(0).resolvePublicKey(null, PublicKeyEntryResolver.IGNORING);
    }

    /**
     * @param  keyType                  The key type - {@code OpenSSH} name - e.g., {@code ssh-rsa, ssh-dss}
     * @param  keySize                  The key size (in bits)
     * @return                          A {@link KeyPair} of the specified type and size
     * @throws GeneralSecurityException If failed to generate the key pair
     * @see                             #getPublicKeyEntryDecoder(String)
     * @see                             PublicKeyEntryDecoder<?, ?>#generateKeyPair(int)
     */
    public static KeyPair generateKeyPair(String keyType, int keySize) throws GeneralSecurityException {
        PublicKeyEntryDecoder<?, ?> decoder = getPublicKeyEntryDecoder(keyType);
        if (decoder == null) {
            throw new InvalidKeySpecException("No decoder for key type=" + keyType);
        }

        return decoder.generateKeyPair(keySize);
    }

    /**
     * Registers the specified decoder for all the types it {@link PublicKeyEntryDecoder<?, ?>#getSupportedKeyTypes()
     * supports}
     *
     * @param decoder The (never {@code null}) {@link PublicKeyEntryDecoder<?, ?> decoder} to register
     * @see           #registerPublicKeyEntryDecoderForKeyType(String, PublicKeyEntryDecoder<?, ?>)
     */
    public static void registerPublicKeyEntryDecoder(PublicKeyEntryDecoder<?, ?> decoder) {
        Objects.requireNonNull(decoder, "No decoder specified");

        Collection<String> names
                = ValidateUtils.checkNotNullAndNotEmpty(decoder.getSupportedKeyTypes(), "No supported key types");
        for (String keyType : names) {
            BY_KEY_TYPE_DECODERS_MAP.put(keyType, decoder);
        }
    }

    /**
     * Unregisters the specified decoder for all the types it supports
     *
     * @param  decoder The (never {@code null}) {@link PublicKeyEntryDecoder<?, ?> decoder} to unregister
     * @return         {@link Set} of all the effectively un-registered key types out of all the
     *                 {@link PublicKeyEntryDecoder<?, ?>#getSupportedKeyTypes() supported} ones.
     * @see            #unregisterPublicKeyEntryDecoderForKeyType(String)
     */
    public static Set<String> unregisterPublicKeyEntryDecoder(PublicKeyEntryDecoder<?, ?> decoder) {
        Objects.requireNonNull(decoder, "No decoder specified");

        Collection<String> names = ValidateUtils.checkNotNullAndNotEmpty(
                decoder.getSupportedKeyTypes(), "No supported key types");
        Set<String> removed = new HashSet<>();
        for (String n : names) {
            PublicKeyEntryDecoder<?, ?> prev = unregisterPublicKeyEntryDecoderForKeyType(n);
            if (prev != null) {
                removed.add(n);
            }
        }
        return removed;
    }

    /**
     * Unregister the decoder registered for the specified key type
     *
     * @param  keyType The key (never {@code null}/empty) key type
     * @return         The unregistered {@link PublicKeyEntryDecoder<?, ?>} - {@code null} if none registered for this
     *                 key type
     */
    public static PublicKeyEntryDecoder<?, ?> unregisterPublicKeyEntryDecoderForKeyType(String keyType) {
        keyType = ValidateUtils.checkNotNullAndNotEmpty(keyType, "No key type specified");
        return BY_KEY_TYPE_DECODERS_MAP.remove(keyType);
    }

    /**
     * @param  keyType The {@code OpenSSH} key type string - e.g., {@code ssh-rsa, ssh-dss} - ignored if
     *                 {@code null}/empty
     * @return         The registered {@link PublicKeyEntryDecoder<?, ?>} or {code null} if not found
     */
    public static PublicKeyEntryDecoder<?, ?> getPublicKeyEntryDecoder(String keyType) {
        if (GenericUtils.isEmpty(keyType)) {
            return null;
        }
        return BY_KEY_TYPE_DECODERS_MAP.get(keyType);
    }

    /**
     * @param  kp The {@link KeyPair} to examine - ignored if {@code null}
     * @return    The matching {@link PublicKeyEntryDecoder<?, ?>} provided <U>both</U> the public and private keys have
     *            the same decoder - {@code null} if no match found
     * @see       #getPublicKeyEntryDecoder(Key)
     */
    public static PublicKeyEntryDecoder<?, ?> getPublicKeyEntryDecoder(KeyPair kp) {
        if (kp == null) {
            return null;
        }

        PublicKeyEntryDecoder<?, ?> d1 = getPublicKeyEntryDecoder(kp.getPublic());
        PublicKeyEntryDecoder<?, ?> d2 = getPublicKeyEntryDecoder(kp.getPrivate());
        if (d1 == d2) {
            return d1;
        } else {
            return null; // some kind of mixed keys...
        }
    }

    /**
     * @param  key The {@link Key} (public or private) - ignored if {@code null}
     * @return     The registered {@link PublicKeyEntryDecoder<?, ?>} for this key or {code null} if no match found
     * @see        #getPublicKeyEntryDecoder(Class)
     */
    public static PublicKeyEntryDecoder<?, ?> getPublicKeyEntryDecoder(Key key) {
        if (key == null) {
            return null;
        }
        return getPublicKeyEntryDecoder(KeyUtils.getKeyType(key));
    }

    /**
     * @return The default {@link DigestFactory} by the {@link #getFingerPrint(PublicKey)} and
     *         {@link #getFingerPrint(String)} methods
     * @see    #KEY_FINGERPRINT_FACTORY_PROP
     * @see    #setDefaultFingerPrintFactory(DigestFactory)
     */
    public static DigestFactory getDefaultFingerPrintFactory() {
        DigestFactory factory = null;
        synchronized (DEFAULT_DIGEST_HOLDER) {
            factory = DEFAULT_DIGEST_HOLDER.get();
            if (factory != null) {
                return factory;
            }

            String propVal = System.getProperty(KEY_FINGERPRINT_FACTORY_PROP);
            if (GenericUtils.isEmpty(propVal)) {
                factory = DEFAULT_FINGERPRINT_DIGEST_FACTORY;
            } else {
                factory = ValidateUtils.checkNotNull(BuiltinDigests.fromFactoryName(propVal), "Unknown digest factory: %s",
                        propVal);
            }

            ValidateUtils.checkTrue(factory.isSupported(), "Selected fingerprint digest not supported: %s", factory.getName());
            DEFAULT_DIGEST_HOLDER.set(factory);
        }

        return factory;
    }

    /**
     * @param f The {@link DigestFactory} of {@link Digest}s to be used - may not be {@code null}
     */
    public static void setDefaultFingerPrintFactory(DigestFactory f) {
        synchronized (DEFAULT_DIGEST_HOLDER) {
            DEFAULT_DIGEST_HOLDER.set(Objects.requireNonNull(f, "No digest factory"));
        }
    }

    /**
     * @param  key the public key - ignored if {@code null}
     * @return     the fingerprint or {@code null} if no key. <B>Note:</B> if exception encountered then returns the
     *             exception's simple class name
     * @see        #getFingerPrint(Factory, PublicKey)
     */
    public static String getFingerPrint(PublicKey key) {
        return getFingerPrint(getDefaultFingerPrintFactory(), key);
    }

    /**
     * @param  password The {@link String} to digest - ignored if {@code null}/empty, otherwise its UTF-8 representation
     *                  is used as input for the fingerprint
     * @return          The fingerprint - {@code null} if {@code null}/empty input. <B>Note:</B> if exception
     *                  encountered then returns the exception's simple class name
     * @see             #getFingerPrint(String, Charset)
     */
    public static String getFingerPrint(String password) {
        return getFingerPrint(password, StandardCharsets.UTF_8);
    }

    /**
     * @param  password The {@link String} to digest - ignored if {@code null}/empty
     * @param  charset  The {@link Charset} to use in order to convert the string to its byte representation to use as
     *                  input for the fingerprint
     * @return          The fingerprint - {@code null} if {@code null}/empty input. <B>Note:</B> if exception
     *                  encountered then returns the exception's simple class name
     * @see             #getFingerPrint(Factory, String, Charset)
     * @see             #getDefaultFingerPrintFactory()
     */
    public static String getFingerPrint(String password, Charset charset) {
        return getFingerPrint(getDefaultFingerPrintFactory(), password, charset);
    }

    /**
     * @param  f   The {@link Factory} to create the {@link Digest} to use
     * @param  key the public key - ignored if {@code null}
     * @return     the fingerprint or {@code null} if no key. <B>Note:</B> if exception encountered then returns the
     *             exception's simple class name
     * @see        #getFingerPrint(Digest, PublicKey)
     */
    public static String getFingerPrint(Factory<? extends Digest> f, PublicKey key) {
        return (key == null) ? null : getFingerPrint(Objects.requireNonNull(f, "No digest factory").create(), key);
    }

    /**
     * @param  d   The {@link Digest} to use
     * @param  key the public key - ignored if {@code null}
     * @return     the fingerprint or {@code null} if no key. <B>Note:</B> if exception encountered then returns the
     *             exception's simple class name
     * @see        DigestUtils#getFingerPrint(Digest, byte[], int, int)
     */
    public static String getFingerPrint(Digest d, PublicKey key) {
        if (key == null) {
            return null;
        }

        try {
            Buffer buffer = new ByteArrayBuffer();
            buffer.putRawPublicKey(key);
            return DigestUtils.getFingerPrint(d, buffer.array(), 0, buffer.wpos());
        } catch (Exception e) {
            return e.toString();
        }
    }

    public static byte[] getRawFingerprint(PublicKey key) throws Exception {
        return getRawFingerprint(getDefaultFingerPrintFactory(), key);
    }

    public static byte[] getRawFingerprint(Factory<? extends Digest> f, PublicKey key) throws Exception {
        return (key == null) ? null : getRawFingerprint(Objects.requireNonNull(f, "No digest factory").create(), key);
    }

    public static byte[] getRawFingerprint(Digest d, PublicKey key) throws Exception {
        if (key == null) {
            return null;
        }

        Buffer buffer = new ByteArrayBuffer();
        buffer.putRawPublicKey(key);
        return DigestUtils.getRawFingerprint(d, buffer.array(), 0, buffer.wpos());
    }

    /**
     * @param  f The {@link Factory} to create the {@link Digest} to use
     * @param  s The {@link String} to digest - ignored if {@code null}/empty, otherwise its UTF-8 representation is
     *           used as input for the fingerprint
     * @return   The fingerprint - {@code null} if {@code null}/empty input. <B>Note:</B> if exception encountered then
     *           returns the exception's simple class name
     * @see      #getFingerPrint(Digest, String, Charset)
     */
    public static String getFingerPrint(Factory<? extends Digest> f, String s) {
        return getFingerPrint(f, s, StandardCharsets.UTF_8);
    }

    /**
     * @param  f       The {@link Factory} to create the {@link Digest} to use
     * @param  s       The {@link String} to digest - ignored if {@code null}/empty
     * @param  charset The {@link Charset} to use in order to convert the string to its byte representation to use as
     *                 input for the fingerprint
     * @return         The fingerprint - {@code null} if {@code null}/empty input <B>Note:</B> if exception encountered
     *                 then returns the exception's simple class name
     * @see            DigestUtils#getFingerPrint(Digest, String, Charset)
     */
    public static String getFingerPrint(Factory<? extends Digest> f, String s, Charset charset) {
        return getFingerPrint(f.create(), s, charset);
    }

    /**
     * @param  d The {@link Digest} to use
     * @param  s The {@link String} to digest - ignored if {@code null}/empty, otherwise its UTF-8 representation is
     *           used as input for the fingerprint
     * @return   The fingerprint - {@code null} if {@code null}/empty input. <B>Note:</B> if exception encountered then
     *           returns the exception's simple class name
     * @see      DigestUtils#getFingerPrint(Digest, String, Charset)
     */
    public static String getFingerPrint(Digest d, String s) {
        return getFingerPrint(d, s, StandardCharsets.UTF_8);
    }

    /**
     * @param  d       The {@link Digest} to use to calculate the fingerprint
     * @param  s       The string to digest - ignored if {@code null}/empty
     * @param  charset The {@link Charset} to use in order to convert the string to its byte representation to use as
     *                 input for the fingerprint
     * @return         The fingerprint - {@code null} if {@code null}/empty input. <B>Note:</B> if exception encountered
     *                 then returns the exception's simple class name
     * @see            DigestUtils#getFingerPrint(Digest, String, Charset)
     */
    public static String getFingerPrint(Digest d, String s, Charset charset) {
        if (GenericUtils.isEmpty(s)) {
            return null;
        }

        try {
            return DigestUtils.getFingerPrint(d, s, charset);
        } catch (Exception e) {
            return e.getClass().getSimpleName();
        }
    }

    /**
     * @param  expected The expected fingerprint if {@code null} or empty then returns a failure with the default
     *                  fingerprint.
     * @param  key      the {@link PublicKey} - if {@code null} then returns null.
     * @return          SimpleImmutableEntry<Boolean, String> - key is success indicator, value is actual fingerprint,
     *                  {@code null} if no key.
     * @see             #getDefaultFingerPrintFactory()
     * @see             #checkFingerPrint(String, Factory, PublicKey)
     */
    public static SimpleImmutableEntry<Boolean, String> checkFingerPrint(String expected, PublicKey key) {
        return checkFingerPrint(expected, getDefaultFingerPrintFactory(), key);
    }

    /**
     * @param  expected The expected fingerprint if {@code null} or empty then returns a failure with the default
     *                  fingerprint.
     * @param  f        The {@link Factory} to be used to generate the default {@link Digest} for the key
     * @param  key      the {@link PublicKey} - if {@code null} then returns null.
     * @return          SimpleImmutableEntry<Boolean, String> - key is success indicator, value is actual fingerprint,
     *                  {@code null} if no key.
     */
    public static SimpleImmutableEntry<Boolean, String> checkFingerPrint(
            String expected, Factory<? extends Digest> f, PublicKey key) {
        return checkFingerPrint(expected, Objects.requireNonNull(f, "No digest factory").create(), key);
    }

    /**
     * @param  expected The expected fingerprint if {@code null} or empty then returns a failure with the default
     *                  fingerprint.
     * @param  d        The {@link Digest} to be used to generate the default fingerprint for the key
     * @param  key      the {@link PublicKey} - if {@code null} then returns null.
     * @return          SimpleImmutableEntry<Boolean, String> - key is success indicator, value is actual fingerprint,
     *                  {@code null} if no key.
     */
    public static SimpleImmutableEntry<Boolean, String> checkFingerPrint(String expected, Digest d, PublicKey key) {
        if (key == null) {
            return null;
        }

        if (GenericUtils.isEmpty(expected)) {
            return new SimpleImmutableEntry<>(false, getFingerPrint(d, key));
        }

        // de-construct fingerprint
        int pos = expected.indexOf(':');
        if ((pos < 0) || (pos >= (expected.length() - 1))) {
            return new SimpleImmutableEntry<>(false, getFingerPrint(d, key));
        }

        String name = expected.substring(0, pos);
        String value = expected.substring(pos + 1);
        DigestFactory expectedFactory;
        // We know that all digest names have a length > 2 - if 2 (or less) then assume a pure HEX value
        if (name.length() > 2) {
            expectedFactory = BuiltinDigests.fromFactoryName(name);
            if (expectedFactory == null) {
                return new SimpleImmutableEntry<>(false, getFingerPrint(d, key));
            }

            expected = name.toUpperCase() + ":" + value;
        } else {
            expectedFactory = BuiltinDigests.md5;
            expected = expectedFactory.getName().toUpperCase() + ":" + expected;
        }

        String fingerprint = getFingerPrint(expectedFactory, key);
        boolean matches = BuiltinDigests.md5.getName().equals(expectedFactory.getName())
                ? expected.equalsIgnoreCase(fingerprint) // HEX is case insensitive
                : expected.equals(fingerprint);
        return new SimpleImmutableEntry<>(matches, fingerprint);
    }

    /**
     * @param  kp a key pair - ignored if {@code null}. If the private key is non-{@code null} then it is used to
     *            determine the type, otherwise the public one is used.
     * @return    the SSH key type or {@code null} if cannot determine it
     * @see       #getKeyType(Key)
     */
    public static String getKeyType(KeyPair kp) {
        if (kp == null) {
            return null;
        }
        PrivateKey key = kp.getPrivate();
        if (key != null) {
            return getKeyType(key);
        } else {
            return getKeyType(kp.getPublic());
        }
    }

    /**
     * @param  key a public or private key
     * @return     the SSH key type or {@code null} if cannot determine it
     */
    public static String getKeyType(Key key) {
        if (key == null) {
            return null;
        } else if (key instanceof SshPublicKey) {
            return ((SshPublicKey) key).getKeyType();
        } else if (key instanceof DSAKey) {
            return KeyPairProvider.SSH_DSS;
        } else if (key instanceof RSAKey) {
            return KeyPairProvider.SSH_RSA;
        } else if (key instanceof ECKey) {
            ECKey ecKey = (ECKey) key;
            ECParameterSpec ecSpec = ecKey.getParams();
            ECCurves curve = ECCurves.fromCurveParameters(ecSpec);
            if (curve == null) {
                return null; // debug breakpoint
            } else {
                return curve.getKeyType();
            }
        } else if (SecurityUtils.EDDSA.equalsIgnoreCase(key.getAlgorithm())
                || SecurityUtils.ED25519.equalsIgnoreCase(key.getAlgorithm())) {
            return KeyPairProvider.SSH_ED25519;
        }

        return null;
    }

    /**
     * @param  keyType A key type name - ignored if {@code null}/empty
     * @return         A {@link List} of they canonical key name and all its aliases
     * @see            #getCanonicalKeyType(String)
     */
    public static List<String> getAllEquivalentKeyTypes(String keyType) {
        if (GenericUtils.isEmpty(keyType)) {
            return Collections.emptyList();
        }

        String canonicalName = getCanonicalKeyType(keyType);
        List<String> equivalents = new ArrayList<>();
        equivalents.add(canonicalName);
        for (Map.Entry<String, String> ae : KEY_TYPE_ALIASES.entrySet()) {
            String alias = ae.getKey();
            String name = ae.getValue();
            if (canonicalName.equalsIgnoreCase(name)) {
                equivalents.add(alias);
            }
        }

        return equivalents;
    }

    /**
     * @param  keyType The available key-type - ignored if {@code null}/empty
     * @return         The canonical key type - same as input if no alias registered for the provided key type
     * @see            #RSA_SHA256_KEY_TYPE_ALIAS
     * @see            #RSA_SHA512_KEY_TYPE_ALIAS
     */
    public static String getCanonicalKeyType(String keyType) {
        if (GenericUtils.isEmpty(keyType)) {
            return keyType;
        }
        String canonicalName = KEY_TYPE_ALIASES.get(keyType);
        if (GenericUtils.isEmpty(canonicalName)) {
            return keyType;
        }
        return canonicalName;
    }

    /**
     * Determines the key size in bits
     *
     * @param  key The {@link Key} to examine - ignored if {@code null}
     * @return     The key size - non-positive value if cannot determine it
     */
    public static int getKeySize(Key key) {
        if (key == null) {
            return -1;
        } else if (key instanceof RSAKey) {
            BigInteger n = ((RSAKey) key).getModulus();
            return n.bitLength();
        } else if (key instanceof DSAKey) {
            DSAParams params = ((DSAKey) key).getParams();
            BigInteger p = params.getP();
            return p.bitLength();
        } else if (key instanceof ECKey) {
            ECParameterSpec ecSpec = ((ECKey) key).getParams();
            ECCurves curve = ECCurves.fromCurveParameters(ecSpec);
            if (curve != null) {
                return curve.getKeySize();
            }
        } else if (SecurityUtils.EDDSA.equalsIgnoreCase(key.getAlgorithm())) {
            return SecurityUtils.getEDDSAKeySize(key);
        }

        return -1;
    }

    /**
     * @param  key    The {@link PublicKey} to be checked - ignored if {@code null}
     * @param  keySet The keys to be searched - ignored if {@code null}/empty
     * @return        The matching {@link PublicKey} from the keys or {@code null} if no match found
     * @see           #compareKeys(PublicKey, PublicKey)
     */
    public static PublicKey findMatchingKey(PublicKey key, PublicKey... keySet) {
        if (key == null || GenericUtils.isEmpty(keySet)) {
            return null;
        } else {
            return findMatchingKey(key, Arrays.asList(keySet));
        }
    }

    /**
     * @param  key    The {@link PublicKey} to be checked - ignored if {@code null}
     * @param  keySet The keys to be searched - ignored if {@code null}/empty
     * @return        The matching {@link PublicKey} from the keys or {@code null} if no match found
     * @see           #compareKeys(PublicKey, PublicKey)
     */
    public static PublicKey findMatchingKey(PublicKey key, Collection<? extends PublicKey> keySet) {
        if (key == null || GenericUtils.isEmpty(keySet)) {
            return null;
        }
        for (PublicKey k : keySet) {
            if (compareKeys(key, k)) {
                return k;
            }
        }
        return null;
    }

    public static boolean compareKeyPairs(KeyPair k1, KeyPair k2) {
        if (Objects.equals(k1, k2)) {
            return true;
        } else if ((k1 == null) || (k2 == null)) {
            return false; // both null is covered by Objects#equals
        }
        return compareKeys(k1.getPublic(), k2.getPublic()) && compareKeys(k1.getPrivate(), k2.getPrivate());
    }

    public static boolean compareKeys(PublicKey k1, PublicKey k2) {
        if (Objects.equals(k1, k2)) {
            return true;
        }
        if ((k1 instanceof RSAPublicKey) && (k2 instanceof RSAPublicKey)) {
            return compareRSAKeys(RSAPublicKey.class.cast(k1), RSAPublicKey.class.cast(k2));
        } else if ((k1 instanceof DSAPublicKey) && (k2 instanceof DSAPublicKey)) {
            return compareDSAKeys(DSAPublicKey.class.cast(k1), DSAPublicKey.class.cast(k2));
        } else if ((k1 instanceof ECPublicKey) && (k2 instanceof ECPublicKey)) {
            return compareECKeys(ECPublicKey.class.cast(k1), ECPublicKey.class.cast(k2));
        } else if ((k1 instanceof SkEcdsaPublicKey) && (k2 instanceof SkEcdsaPublicKey)) {
            return compareSkEcdsaKeys(SkEcdsaPublicKey.class.cast(k1), SkEcdsaPublicKey.class.cast(k2));
        } else if ((k1 != null) && SecurityUtils.EDDSA.equalsIgnoreCase(k1.getAlgorithm())
                && (k2 != null) && SecurityUtils.EDDSA.equalsIgnoreCase(k2.getAlgorithm())) {
            return SecurityUtils.compareEDDSAPPublicKeys(k1, k2);
        } else if ((k1 != null) && SecurityUtils.ED25519.equalsIgnoreCase(k1.getAlgorithm())
                && (k2 != null) && SecurityUtils.ED25519.equalsIgnoreCase(k2.getAlgorithm())) {
            return SecurityUtils.compareEDDSAPPublicKeys(k1, k2);
        } else if ((k1 instanceof SkED25519PublicKey) && (k2 instanceof SkED25519PublicKey)) {
            return compareSkEd25519Keys(SkED25519PublicKey.class.cast(k1), SkED25519PublicKey.class.cast(k2));
        } else if ((k1 instanceof OpenSshCertificate) && (k2 instanceof OpenSshCertificate)) {
            return compareOpenSSHCertificateKeys(OpenSshCertificate.class.cast(k1), OpenSshCertificate.class.cast(k2));
        }
        return false; // either key is null or not of same class
    }

    public static PublicKey recoverPublicKey(PrivateKey key) throws GeneralSecurityException {
        if (key instanceof RSAPrivateKey) {
            return recoverRSAPublicKey((RSAPrivateKey) key);
        } else if (key instanceof DSAPrivateKey) {
            return recoverDSAPublicKey((DSAPrivateKey) key);
        } else if ((key != null) && SecurityUtils.EDDSA.equalsIgnoreCase(key.getAlgorithm())) {
            return SecurityUtils.recoverEDDSAPublicKey(key);
        }
        return null;
    }

    public static boolean compareKeys(PrivateKey k1, PrivateKey k2) {
        if ((k1 instanceof RSAPrivateKey) && (k2 instanceof RSAPrivateKey)) {
            return compareRSAKeys(RSAPrivateKey.class.cast(k1), RSAPrivateKey.class.cast(k2));
        } else if ((k1 instanceof DSAPrivateKey) && (k2 instanceof DSAPrivateKey)) {
            return compareDSAKeys(DSAPrivateKey.class.cast(k1), DSAPrivateKey.class.cast(k2));
        } else if ((k1 instanceof ECPrivateKey) && (k2 instanceof ECPrivateKey)) {
            return compareECKeys(ECPrivateKey.class.cast(k1), ECPrivateKey.class.cast(k2));
        } else if ((k1 != null) && SecurityUtils.EDDSA.equalsIgnoreCase(k1.getAlgorithm())
                && (k2 != null) && SecurityUtils.EDDSA.equalsIgnoreCase(k2.getAlgorithm())) {
            return SecurityUtils.compareEDDSAPrivateKeys(k1, k2);
        }
        return false; // either key is null or not of same class
    }

    public static boolean compareRSAKeys(RSAPublicKey k1, RSAPublicKey k2) {
        if (Objects.equals(k1, k2)) {
            return true;
        } else if (k1 == null || k2 == null) {
            return false; // both null is covered by Objects#equals
        }
        return Objects.equals(k1.getPublicExponent(), k2.getPublicExponent())
                && Objects.equals(k1.getModulus(), k2.getModulus());
    }

    public static boolean compareRSAKeys(RSAPrivateKey k1, RSAPrivateKey k2) {
        if (Objects.equals(k1, k2)) {
            return true;
        } else if (k1 == null || k2 == null) {
            return false; // both null is covered by Objects#equals
        }
        return Objects.equals(k1.getModulus(), k2.getModulus())
                && Objects.equals(k1.getPrivateExponent(), k2.getPrivateExponent());
    }

    public static boolean compareOpenSSHCertificateKeys(OpenSshCertificate k1, OpenSshCertificate k2) {
        if (k1 == k2) {
            return true;
        } else if (k1 == null || k2 == null) {
            return false; // both null is covered above
        }
        return Objects.equals(k1.getSerial(), k2.getSerial()) && Arrays.equals(k1.getSignature(), k2.getSignature())
                && compareKeys(k1.getCertPubKey(), k2.getCertPubKey());
    }

    public static RSAPublicKey recoverRSAPublicKey(RSAPrivateKey privateKey) throws GeneralSecurityException {
        if (privateKey instanceof RSAPrivateCrtKey) {
            return recoverFromRSAPrivateCrtKey((RSAPrivateCrtKey) privateKey);
        } else {
            // Not ideal, but best we can do under the circumstances
            return recoverRSAPublicKey(privateKey.getModulus(), DEFAULT_RSA_PUBLIC_EXPONENT);
        }
    }

    public static RSAPublicKey recoverFromRSAPrivateCrtKey(RSAPrivateCrtKey rsaKey) throws GeneralSecurityException {
        return recoverRSAPublicKey(rsaKey.getPrimeP(), rsaKey.getPrimeQ(), rsaKey.getPublicExponent());
    }

    public static RSAPublicKey recoverRSAPublicKey(BigInteger p, BigInteger q, BigInteger publicExponent)
            throws GeneralSecurityException {
        return recoverRSAPublicKey(p.multiply(q), publicExponent);
    }

    public static RSAPublicKey recoverRSAPublicKey(BigInteger modulus, BigInteger publicExponent)
            throws GeneralSecurityException {
        KeyFactory kf = SecurityUtils.getKeyFactory(RSA_ALGORITHM);
        return (RSAPublicKey) kf.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
    }

    public static boolean compareDSAKeys(DSAPublicKey k1, DSAPublicKey k2) {
        if (Objects.equals(k1, k2)) {
            return true;
        } else if (k1 == null || k2 == null) {
            return false; // both null is covered by Objects#equals
        }
        return Objects.equals(k1.getY(), k2.getY()) && compareDSAParams(k1.getParams(), k2.getParams());
    }

    public static boolean compareDSAKeys(DSAPrivateKey k1, DSAPrivateKey k2) {
        if (Objects.equals(k1, k2)) {
            return true;
        } else if (k1 == null || k2 == null) {
            return false; // both null is covered by Objects#equals
        }
        return Objects.equals(k1.getX(), k2.getX()) && compareDSAParams(k1.getParams(), k2.getParams());
    }

    public static boolean compareDSAParams(DSAParams p1, DSAParams p2) {
        if (Objects.equals(p1, p2)) {
            return true;
        } else if (p1 == null || p2 == null) {
            return false; // both null is covered by Objects#equals
        }
        return Objects.equals(p1.getG(), p2.getG()) && Objects.equals(p1.getP(), p2.getP())
                && Objects.equals(p1.getQ(), p2.getQ());
    }

    // based on code from
    // https://github.com/alexo/SAML-2.0/blob/master/java-opensaml/opensaml-security-api/src/main/java/org/opensaml/xml/security/SecurityHelper.java
    public static DSAPublicKey recoverDSAPublicKey(DSAPrivateKey privateKey) throws GeneralSecurityException {
        DSAParams keyParams = privateKey.getParams();
        BigInteger p = keyParams.getP();
        BigInteger x = privateKey.getX();
        BigInteger q = keyParams.getQ();
        BigInteger g = keyParams.getG();
        BigInteger y = g.modPow(x, p);
        KeyFactory kf = SecurityUtils.getKeyFactory(DSS_ALGORITHM);
        return (DSAPublicKey) kf.generatePublic(new DSAPublicKeySpec(y, p, q, g));
    }

    public static boolean compareECKeys(ECPrivateKey k1, ECPrivateKey k2) {
        if (Objects.equals(k1, k2)) {
            return true;
        } else if (k1 == null || k2 == null) {
            return false; // both null is covered by Objects#equals
        }
        return Objects.equals(k1.getS(), k2.getS()) && compareECParams(k1.getParams(), k2.getParams());
    }

    public static boolean compareECKeys(ECPublicKey k1, ECPublicKey k2) {
        if (Objects.equals(k1, k2)) {
            return true;
        } else if (k1 == null || k2 == null) {
            return false; // both null is covered by Objects#equals
        }
        return Objects.equals(k1.getW(), k2.getW()) && compareECParams(k1.getParams(), k2.getParams());
    }

    public static boolean compareECParams(ECParameterSpec s1, ECParameterSpec s2) {
        if (Objects.equals(s1, s2)) {
            return true;
        } else if (s1 == null || s2 == null) {
            return false; // both null is covered by Objects#equals
        }
        return Objects.equals(s1.getOrder(), s2.getOrder()) && (s1.getCofactor() == s2.getCofactor())
                && Objects.equals(s1.getGenerator(), s2.getGenerator()) && Objects.equals(s1.getCurve(), s2.getCurve());
    }

    public static boolean compareSkEcdsaKeys(SkEcdsaPublicKey k1, SkEcdsaPublicKey k2) {
        if (Objects.equals(k1, k2)) {
            return true;
        } else if (k1 == null || k2 == null) {
            return false; // both null is covered by Objects#equals
        }
        return Objects.equals(k1.getAppName(), k2.getAppName())
                && Objects.equals(k1.isNoTouchRequired(), k2.isNoTouchRequired())
                && compareECKeys(k1.getDelegatePublicKey(), k2.getDelegatePublicKey());
    }

    public static boolean compareSkEd25519Keys(SkED25519PublicKey k1, SkED25519PublicKey k2) {
        if (Objects.equals(k1, k2)) {
            return true;
        } else if (k1 == null || k2 == null) {
            return false; // both null is covered by Objects#equals
        }
        return Objects.equals(k1.getAppName(), k2.getAppName())
                && Objects.equals(k1.isNoTouchRequired(), k2.isNoTouchRequired())
                && SecurityUtils.compareEDDSAPPublicKeys(k1.getDelegatePublicKey(), k2.getDelegatePublicKey());
    }

    public static String getSignatureAlgorithm(String chosenAlgorithm) {
        String mapped = SIGNATURE_ALGORITHM_MAP.get(chosenAlgorithm);
        return mapped == null ? chosenAlgorithm : mapped;
    }

    public static boolean isCertificateAlgorithm(String algorithm) {
        return SIGNATURE_ALGORITHM_MAP.containsKey(algorithm);
    }
}
