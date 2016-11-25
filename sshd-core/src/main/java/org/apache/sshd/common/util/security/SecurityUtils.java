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
package org.apache.sshd.common.util.security;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.DHParameterSpec;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PrivateKeyEntryDecoder;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceParser;
import org.apache.sshd.common.config.keys.loader.openssh.OpenSSHKeyPairResourceParser;
import org.apache.sshd.common.config.keys.loader.pem.PEMResourceParserUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.random.JceRandomFactory;
import org.apache.sshd.common.random.RandomFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ReflectionUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.security.bouncycastle.BouncyCastleGeneratorHostKeyProvider;
import org.apache.sshd.common.util.security.bouncycastle.BouncyCastleKeyPairResourceParser;
import org.apache.sshd.common.util.security.bouncycastle.BouncyCastleRandomFactory;
import org.apache.sshd.common.util.security.eddsa.EdDSASecurityProvider;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.keyprovider.AbstractGeneratorHostKeyProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Specific security providers related code
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class SecurityUtils {
    /**
     * Bouncycastle JCE provider name
     */
    public static final String BOUNCY_CASTLE = "BC";

    /**
     * EDDSA support
     */
    public static final String EDDSA = "EdDSA";

    /**
     * System property used to configure the value for the maximum supported Diffie-Hellman
     * Group Exchange key size. If not set, then an internal auto-discovery mechanism is employed.
     * If set to negative value then Diffie-Hellman Group Exchange is disabled. If set to a
     * negative value then Diffie-Hellman Group Exchange is disabled
     */
    public static final String MAX_DHGEX_KEY_SIZE_PROP = "org.apache.sshd.maxDHGexKeySize";

    /**
     * The min. key size value used for testing whether Diffie-Hellman Group Exchange
     * is supported or not. According to <A HREF="https://tools.ietf.org/html/rfc4419">RFC 4419</A>
     * section 3: &quot;Servers and clients SHOULD support groups with a modulus length of k
     * bits, where 1024 <= k <= 8192&quot;.
     * </code>
     */
    public static final int MIN_DHGEX_KEY_SIZE = 1024;
    // Keys of size > 1024 are not support by default with JCE
    public static final int DEFAULT_DHGEX_KEY_SIZE = MIN_DHGEX_KEY_SIZE;
    public static final int PREFERRED_DHGEX_KEY_SIZE = 4096;
    public static final int MAX_DHGEX_KEY_SIZE = 8192;

    /**
     * System property used to control whether to automatically register the
     * {@code Bouncyastle} JCE provider
     */
    public static final String REGISTER_BOUNCY_CASTLE_PROP = "org.apache.sshd.registerBouncyCastle";

    /**
     * System property used to control whether Elliptic Curves are supported or not.
     * If not set then the support is auto-detected. <B>Note:</B> if set to {@code true}
     * it is up to the user to make sure that indeed there is a provider for them
     */
    public static final String ECC_SUPPORTED_PROP = "org.apache.sshd.eccSupport";

    /**
     * System property used to decide whether EDDSA curves are supported or not
     * (in addition or even in spite of {@link #isEDDSACurveSupported()}). If not
     * set or set to {@code true}, then the existence of the optional support classes
     * determines the support.
     */
    public static final String EDDSA_SUPPORTED_PROP = "org.apache.sshd.eddsaSupport";

    private static final AtomicInteger MAX_DHG_KEY_SIZE_HOLDER = new AtomicInteger(0);

    private static final Map<String, Provider> REGISTERED_PROVIDERS = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private static final AtomicReference<KeyPairResourceParser> KEYPAIRS_PARSER_HODLER = new AtomicReference<>();

    private static String defaultProvider;
    private static Boolean registerBouncyCastle;
    private static boolean registrationDone;
    private static Boolean hasEcc;
    private static Boolean eddsaSupported;

    private SecurityUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * @return {@code true} if Elliptic Curve Cryptography is supported
     * @see #ECC_SUPPORTED_PROP
     */
    public static boolean hasEcc() {
        if (hasEcc == null) {
            String propValue = System.getProperty(ECC_SUPPORTED_PROP);
            if (GenericUtils.isEmpty(propValue)) {
                try {
                    getKeyPairGenerator(KeyUtils.EC_ALGORITHM);
                    hasEcc = Boolean.TRUE;
                } catch (Throwable t) {
                    hasEcc = Boolean.FALSE;
                }
            } else {
                Logger logger = LoggerFactory.getLogger(SecurityUtils.class);
                logger.info("Override ECC support value: " + propValue);
                hasEcc = Boolean.valueOf(propValue);
            }
        }

        return hasEcc;
    }

    /**
     * @return {@code true} if Diffie-Hellman Group Exchange is supported
     * @see #getMaxDHGroupExchangeKeySize()
     */
    public static boolean isDHGroupExchangeSupported() {
        return getMaxDHGroupExchangeKeySize() > 0;
    }

    /**
     * @param keySize The expected key size
     * @return {@code true} if Oakely Diffie-Hellman Group Exchange is supported
     * for the specified key size
     * @see #getMaxDHGroupExchangeKeySize()
     */
    public static boolean isDHOakelyGroupSupported(int keySize) {
        return getMaxDHGroupExchangeKeySize() >= keySize;
    }

    /**
     * @return The maximum supported Diffie-Hellman Group Exchange key size,
     * or non-positive if not supported
     */
    public static int getMaxDHGroupExchangeKeySize() {
        int maxSupportedKeySize;
        synchronized (MAX_DHG_KEY_SIZE_HOLDER) {
            maxSupportedKeySize = MAX_DHG_KEY_SIZE_HOLDER.get();
            if (maxSupportedKeySize != 0) { // 1st time we are called ?
                return maxSupportedKeySize;
            }

            String propValue = System.getProperty(MAX_DHGEX_KEY_SIZE_PROP);
            if (GenericUtils.isEmpty(propValue)) {
                maxSupportedKeySize = -1;
                // Go down from max. to min. to ensure we stop at 1st maximum value success
                for (int testKeySize = MAX_DHGEX_KEY_SIZE; testKeySize >= MIN_DHGEX_KEY_SIZE; testKeySize -= 1024) {
                    if (isDHGroupExchangeSupported(testKeySize)) {
                        maxSupportedKeySize = testKeySize;
                        break;
                    }
                }
            } else {
                Logger logger = LoggerFactory.getLogger(SecurityUtils.class);
                logger.info("Override max. DH group exchange key size: " + propValue);
                maxSupportedKeySize = Integer.parseInt(propValue);
                // negative is OK - means user wants to disable DH group exchange
                ValidateUtils.checkTrue(maxSupportedKeySize != 0,
                        "Configured " + MAX_DHGEX_KEY_SIZE_PROP + " value must be non-zero: %d", maxSupportedKeySize);
            }

            MAX_DHG_KEY_SIZE_HOLDER.set(maxSupportedKeySize);
        }

        return maxSupportedKeySize;
    }

    /**
     * Set programmatically the reported value for {@link #getMaxDHGroupExchangeKeySize()}
     * @param keySize The reported key size - if zero, then it will be auto-detected, if
     * negative then DH group exchange will be disabled
     */
    public static void setMaxDHGroupExchangeKeySize(int keySize) {
        synchronized (MAX_DHG_KEY_SIZE_HOLDER) {
            MAX_DHG_KEY_SIZE_HOLDER.set(keySize);
        }
    }

    public static boolean isDHGroupExchangeSupported(int maxKeySize) {
        ValidateUtils.checkTrue(maxKeySize > Byte.SIZE, "Invalid max. key size: %d", maxKeySize);

        try {
            BigInteger r = new BigInteger("0").setBit(maxKeySize - 1);
            DHParameterSpec dhSkipParamSpec = new DHParameterSpec(r, r);
            KeyPairGenerator kpg = getKeyPairGenerator("DH");
            kpg.initialize(dhSkipParamSpec);
            return true;
        } catch (GeneralSecurityException t) {
            return false;
        }
    }

    public static synchronized void setRegisterBouncyCastle(boolean registerBouncyCastle) {
        SecurityUtils.registerBouncyCastle = registerBouncyCastle;
        registrationDone = false;
    }

    public static synchronized String getDefaultProvider() {
        return defaultProvider;
    }

    public static synchronized void setDefaultProvider(String provider) {
        defaultProvider = provider;
        registrationDone = false;
    }

    /**
     * @return A <U>copy</U> of the currently registered security providers
     */
    public static synchronized Set<String> getRegisteredProviders() {
        register();

        // returns a COPY of the providers in order to avoid modifications
        synchronized (REGISTERED_PROVIDERS) {
            return new TreeSet<>(REGISTERED_PROVIDERS.keySet());
        }
    }

    public static synchronized boolean isBouncyCastleRegistered() {
        register();
        return isBouncyCastleListed();
    }

    private static boolean isBouncyCastleListed() {
        return isProviderRegistered(BOUNCY_CASTLE);
    }

    private static boolean isEDDSAListed() {
        return isProviderRegistered(EDDSA);
    }

    private static boolean isProviderRegistered(String provider) {
        Objects.requireNonNull(provider, "No provider name specified");
        synchronized (REGISTERED_PROVIDERS) {
            return REGISTERED_PROVIDERS.containsKey(provider);
        }
    }

    @SuppressWarnings("synthetic-access")
    private static void register() {
        if (!registrationDone) {
            if (registerBouncyCastle == null) {
                String propValue = System.getProperty(REGISTER_BOUNCY_CASTLE_PROP);
                if (!GenericUtils.isEmpty(propValue)) {
                    Logger logger = LoggerFactory.getLogger(SecurityUtils.class);
                    logger.info("Override BouncyCastle registration value: " + propValue);
                    registerBouncyCastle = Boolean.valueOf(propValue);
                }
            }

            if ((defaultProvider == null) && (!isBouncyCastleListed()) && ((registerBouncyCastle == null) || registerBouncyCastle)) {
                // Use an inner class to avoid a strong dependency from SshServer on BouncyCastle
                try {
                    new BouncyCastleRegistration().call();
                    defaultProvider = BOUNCY_CASTLE;
                } catch (Throwable t) {
                    Logger logger = LoggerFactory.getLogger(SecurityUtils.class);
                    if (registerBouncyCastle == null) {
                        logger.info("BouncyCastle not registered, using the default JCE provider");
                    } else {
                        logger.error("Failed {} to register BouncyCastle as a JCE provider: {}", t.getClass().getSimpleName(), t.getMessage());
                        throw new RuntimeException("Failed to register BouncyCastle as a JCE provider", t);
                    }
                }
            }

            if ((!isEDDSAListed()) && isEDDSACurveSupported()) {
                try {
                    new EdDSARegistration().call();
                } catch (Throwable t) {
                    Logger logger = LoggerFactory.getLogger(SecurityUtils.class);
                    logger.error("Failed {} to register " + EDDSA + " as a JCE provider: {}", t.getClass().getSimpleName(), t.getMessage());
                    throw new RuntimeException("Failed to register " + EDDSA + " as a JCE provider", t);
                }
            }

            registrationDone = true;
        }
    }

    ///////////////// Bouncycastle specific implementations //////////////////

    private static class BouncyCastleRegistration implements Callable<Void> {
        @SuppressWarnings("synthetic-access")
        @Override
        public Void call() throws Exception {
            // no need for a logger specific to this class since this is a one-time call
            Logger logger = LoggerFactory.getLogger(SecurityUtils.class);
            Provider p = java.security.Security.getProvider(BOUNCY_CASTLE);
            if (p == null) {
                logger.info("Trying to register BouncyCastle as a JCE provider");
                p = new BouncyCastleProvider();
                java.security.Security.addProvider(p);
                MessageDigest.getInstance("MD5", BOUNCY_CASTLE);
                KeyAgreement.getInstance("DH", BOUNCY_CASTLE);
                logger.info("Registration succeeded");
            } else {
                logger.info("BouncyCastle already registered as a JCE provider");
            }

            synchronized (REGISTERED_PROVIDERS) {
                REGISTERED_PROVIDERS.put(BOUNCY_CASTLE, p);
            }
            return null;
        }
    }

    /* -------------------------------------------------------------------- */

    /**
     * @param resourceKey An identifier of the key being loaded - used as
     *                    argument to the {@link FilePasswordProvider#getPassword(String)}
     *                    invocation
     * @param inputStream The {@link InputStream} for the <U>private</U> key
     * @param provider    A {@link FilePasswordProvider} - may be {@code null}
     *                    if the loaded key is <U>guaranteed</U> not to be encrypted
     * @return The loaded {@link KeyPair}
     * @throws IOException              If failed to read/parse the input stream
     * @throws GeneralSecurityException If failed to generate the keys
     */
    public static KeyPair loadKeyPairIdentity(String resourceKey, InputStream inputStream, FilePasswordProvider provider)
            throws IOException, GeneralSecurityException {
        KeyPairResourceParser parser = getKeyPairResourceParser();
        if (parser == null) {
            throw new NoSuchProviderException("No registered key-pair resource parser");
        }

        Collection<KeyPair> ids = parser.loadKeyPairs(resourceKey, provider, inputStream);
        int numLoaded = GenericUtils.size(ids);
        if (numLoaded <= 0) {
            throw new InvalidKeyException("Unsupported private key file format: " + resourceKey);
        }
        if (numLoaded != 1) {
            throw new InvalidKeySpecException("Multiple private key pairs N/A: " + resourceKey);
        }

        return ids.iterator().next();
    }

    /* -------------------------------------------------------------------- */

    public static AbstractGeneratorHostKeyProvider createGeneratorHostKeyProvider(Path path) {
        ValidateUtils.checkTrue(isBouncyCastleRegistered(), "BouncyCastle not registered");
        return new BouncyCastleGeneratorHostKeyProvider(path);
    }

    public static KeyPairResourceParser getBouncycastleKeyPairResourceParser() {
        ValidateUtils.checkTrue(isBouncyCastleRegistered(), "BouncyCastle not registered");
        return BouncyCastleKeyPairResourceParser.INSTANCE;
    }

    /**
     * @return If {@link #isBouncyCastleRegistered()} then a {@link BouncyCastleRandomFactory}
     * instance, otherwise a {@link JceRandomFactory} one
     */
    public static RandomFactory getRandomFactory() {
        if (isBouncyCastleRegistered()) {
            return BouncyCastleRandomFactory.INSTANCE;
        } else {
            return JceRandomFactory.INSTANCE;
        }
    }

    ///////////////////////////// ED25519 support ///////////////////////////////

    /**
     * @return {@code true} if EDDSA curves (e.g., {@code ed25519}) are supported
     */
    public static synchronized boolean isEDDSACurveSupported() {
        if (eddsaSupported == null) {
            String propValue = System.getProperty(EDDSA_SUPPORTED_PROP);
            if (GenericUtils.isEmpty(propValue) || "true".equals(propValue)) {
                ClassLoader cl = ThreadUtils.resolveDefaultClassLoader(SecurityUtils.class);
                eddsaSupported = ReflectionUtils.isClassAvailable(cl, "net.i2p.crypto.eddsa.EdDSAKey");
            } else {
                eddsaSupported = Boolean.FALSE;
                Logger logger = LoggerFactory.getLogger(SecurityUtils.class);
                logger.info("Override EDDSA support value: " + propValue);
            }
        }

        return eddsaSupported;
    }

    /* -------------------------------------------------------------------- */

    private static class EdDSARegistration implements Callable<Void> {
        EdDSARegistration() {
            super();
        }

        @SuppressWarnings("synthetic-access")
        @Override
        public Void call() throws Exception {
            // no need for a logger specific to this class since this is a one-time call
            Logger logger = LoggerFactory.getLogger(SecurityUtils.class);
            Provider p = java.security.Security.getProvider(EDDSA);
            if (p == null) {
                logger.info("Trying to register " + EDDSA + " as a JCE provider");
                p = new EdDSASecurityProvider();
                java.security.Security.addProvider(p);
                KeyFactory.getInstance(EDDSA, EDDSA);
                logger.info("Registration succeeded");
            } else {
                logger.info(EDDSA + " already registered as a JCE provider");
            }

            synchronized (REGISTERED_PROVIDERS) {
                REGISTERED_PROVIDERS.put(EDDSA, p);
            }

            return null;
        }
    }

    /* -------------------------------------------------------------------- */

    public static PublicKeyEntryDecoder<? extends PublicKey, ? extends PrivateKey> getEDDSAPublicKeyEntryDecoder() {
        if (!isEDDSACurveSupported()) {
            throw new UnsupportedOperationException(EDDSA + " provider N/A");
        }

        return EdDSASecurityProvider.getEDDSAPublicKeyEntryDecoder();
    }

    public static PrivateKeyEntryDecoder<? extends PublicKey, ? extends PrivateKey> getOpenSSHEDDSAPrivateKeyEntryDecoder() {
        if (!isEDDSACurveSupported()) {
            throw new UnsupportedOperationException(EDDSA + " provider N/A");
        }

        return EdDSASecurityProvider.getOpenSSHEDDSAPrivateKeyEntryDecoder();
    }

    public static org.apache.sshd.common.signature.Signature getEDDSASigner() {
        if (isEDDSACurveSupported()) {
            return EdDSASecurityProvider.getEDDSASignature();
        }

        throw new UnsupportedOperationException(EDDSA + " Signer not available");
    }

    public static int getEDDSAKeySize(Key key) {
        return EdDSASecurityProvider.getEDDSAKeySize(key);
    }

    public static Class<? extends PublicKey> getEDDSAPublicKeyType() {
        return isEDDSACurveSupported() ? EdDSASecurityProvider.getEDDSAPublicKeyType() : PublicKey.class;
    }

    public static Class<? extends PrivateKey> getEDDSAPrivateKeyType() {
        return isEDDSACurveSupported() ? EdDSASecurityProvider.getEDDSAPrivateKeyType() : PrivateKey.class;
    }

    public static boolean compareEDDSAPPublicKeys(PublicKey k1, PublicKey k2) {
        return isEDDSACurveSupported() ? EdDSASecurityProvider.compareEDDSAPPublicKeys(k1, k2) : false;
    }

    public static boolean compareEDDSAPrivateKeys(PrivateKey k1, PrivateKey k2) {
        return isEDDSACurveSupported() ? EdDSASecurityProvider.compareEDDSAPrivateKeys(k1, k2) : false;
    }

    public static PublicKey recoverEDDSAPublicKey(PrivateKey key) throws GeneralSecurityException {
        if (!isEDDSACurveSupported()) {
            throw new NoSuchAlgorithmException(EDDSA + " provider not supported");
        }

        return EdDSASecurityProvider.recoverEDDSAPublicKey(key);
    }

    public static PublicKey generateEDDSAPublicKey(String keyType, byte[] seed) throws GeneralSecurityException {
        if (!KeyPairProvider.SSH_ED25519.equals(keyType)) {
            throw new InvalidKeyException("Unsupported key type: " + keyType);
        }

        if (!isEDDSACurveSupported()) {
            throw new NoSuchAlgorithmException(EDDSA + " provider not supported");
        }

        return EdDSASecurityProvider.generateEDDSAPublicKey(seed);
    }

    public static <B extends Buffer> B putRawEDDSAPublicKey(B buffer, PublicKey key) {
        if (!isEDDSACurveSupported()) {
            throw new UnsupportedOperationException(EDDSA + " provider not supported");
        }

        return EdDSASecurityProvider.putRawEDDSAPublicKey(buffer, key);
    }

    public static <B extends Buffer> B putEDDSAKeyPair(B buffer, KeyPair kp) {
        return putEDDSAKeyPair(buffer, Objects.requireNonNull(kp, "No key pair").getPublic(), kp.getPrivate());
    }

    public static <B extends Buffer> B putEDDSAKeyPair(B buffer, PublicKey pubKey, PrivateKey prvKey) {
        if (!isEDDSACurveSupported()) {
            throw new UnsupportedOperationException(EDDSA + " provider not supported");
        }

        return EdDSASecurityProvider.putEDDSAKeyPair(buffer, pubKey, prvKey);
    }

    public static KeyPair extractEDDSAKeyPair(Buffer buffer, String keyType) throws GeneralSecurityException {
        if (!KeyPairProvider.SSH_ED25519.equals(keyType)) {
            throw new InvalidKeyException("Unsupported key type: " + keyType);
        }

        if (!isEDDSACurveSupported()) {
            throw new NoSuchAlgorithmException(EDDSA + " provider not supported");
        }

        throw new GeneralSecurityException("Full SSHD-440 implementation N/A");
    }

    //////////////////////////////////////////////////////////////////////////

    public static KeyPairResourceParser getKeyPairResourceParser() {
        KeyPairResourceParser parser;
        synchronized (KEYPAIRS_PARSER_HODLER) {
            parser = KEYPAIRS_PARSER_HODLER.get();
            if (parser != null) {
                return parser;
            }

            parser = KeyPairResourceParser.aggregate(
                    PEMResourceParserUtils.PROXY,
                    OpenSSHKeyPairResourceParser.INSTANCE);
            KEYPAIRS_PARSER_HODLER.set(parser);
        }

        return parser;
    }

    /**
     * @param parser The system-wide {@code KeyPairResourceParser} to use.
     * If set to {@code null}, then the default parser will be re-constructed
     * on next call to {@link #getKeyPairResourceParser()}
     */
    public static void setKeyPairResourceParser(KeyPairResourceParser parser) {
        synchronized (KEYPAIRS_PARSER_HODLER) {
            KEYPAIRS_PARSER_HODLER.set(parser);
        }
    }

    public static synchronized KeyFactory getKeyFactory(String algorithm) throws GeneralSecurityException {
        register();

        String providerName = getDefaultProvider();
        if (isEDDSACurveSupported() && EdDSASecurityProvider.isEDDSAKeyFactoryAlgorithm(algorithm)) {
            providerName = EDDSA;
        }

        if (GenericUtils.isEmpty(providerName)) {
            return KeyFactory.getInstance(algorithm);
        } else {
            return KeyFactory.getInstance(algorithm, providerName);
        }
    }

    public static synchronized Cipher getCipher(String transformation) throws GeneralSecurityException {
        register();

        String providerName = getDefaultProvider();
        if (GenericUtils.isEmpty(providerName)) {
            return Cipher.getInstance(transformation);
        } else {
            return Cipher.getInstance(transformation, providerName);
        }
    }

    public static synchronized MessageDigest getMessageDigest(String algorithm) throws GeneralSecurityException {
        register();

        String providerName = getDefaultProvider();
        if (GenericUtils.isEmpty(providerName)) {
            return MessageDigest.getInstance(algorithm);
        } else {
            return MessageDigest.getInstance(algorithm, providerName);
        }
    }

    public static synchronized KeyPairGenerator getKeyPairGenerator(String algorithm) throws GeneralSecurityException {
        register();

        String providerName = getDefaultProvider();
        if (isEDDSACurveSupported() && EdDSASecurityProvider.isEDDSAKeyPairGeneratorAlgorithm(algorithm)) {
            providerName = EDDSA;
        }

        if (GenericUtils.isEmpty(providerName)) {
            return KeyPairGenerator.getInstance(algorithm);
        } else {
            return KeyPairGenerator.getInstance(algorithm, providerName);
        }
    }

    public static synchronized KeyAgreement getKeyAgreement(String algorithm) throws GeneralSecurityException {
        register();

        String providerName = getDefaultProvider();
        if (GenericUtils.isEmpty(providerName)) {
            return KeyAgreement.getInstance(algorithm);
        } else {
            return KeyAgreement.getInstance(algorithm, providerName);
        }
    }

    public static synchronized Mac getMac(String algorithm) throws GeneralSecurityException {
        register();

        String providerName = getDefaultProvider();
        if (GenericUtils.isEmpty(providerName)) {
            return Mac.getInstance(algorithm);
        } else {
            return Mac.getInstance(algorithm, providerName);
        }
    }

    public static synchronized Signature getSignature(String algorithm) throws GeneralSecurityException {
        register();

        String providerName = getDefaultProvider();
        if (isEDDSACurveSupported() && EdDSASecurityProvider.isEDDSASignatureAlgorithm(algorithm)) {
            providerName = EDDSA;
        }

        if (GenericUtils.isEmpty(providerName)) {
            return Signature.getInstance(algorithm);
        } else {
            return Signature.getInstance(algorithm, providerName);
        }
    }

    public static synchronized CertificateFactory getCertificateFactory(String type) throws GeneralSecurityException {
        register();

        String providerName = getDefaultProvider();
        if (GenericUtils.isEmpty(providerName)) {
            return CertificateFactory.getInstance(type);
        } else {
            return CertificateFactory.getInstance(type, providerName);
        }
    }
}
