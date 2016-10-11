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
package org.apache.sshd.common.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
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
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.DHParameterSpec;

import net.i2p.crypto.eddsa.EdDSAKey;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import org.apache.sshd.common.config.keys.AbstractPublicKeyEntryDecoder;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.AbstractClassLoadableResourceKeyPairProvider;
import org.apache.sshd.common.keyprovider.AbstractFileKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.random.AbstractRandom;
import org.apache.sshd.common.random.AbstractRandomFactory;
import org.apache.sshd.common.random.JceRandomFactory;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.random.RandomFactory;
import org.apache.sshd.common.signature.AbstractSignature;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.keyprovider.AbstractGeneratorHostKeyProvider;
import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.crypto.prng.VMPCRandomGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
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

    private static final Set<String> REGISTERED_PROVIDERS = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);

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
            return new TreeSet<>(REGISTERED_PROVIDERS);
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
            return REGISTERED_PROVIDERS.contains(provider);
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
            if (java.security.Security.getProvider(BOUNCY_CASTLE) == null) {
                logger.info("Trying to register BouncyCastle as a JCE provider");
                java.security.Security.addProvider(new BouncyCastleProvider());
                MessageDigest.getInstance("MD5", BOUNCY_CASTLE);
                KeyAgreement.getInstance("DH", BOUNCY_CASTLE);
                logger.info("Registration succeeded");
            } else {
                logger.info("BouncyCastle already registered as a JCE provider");
            }

            synchronized (REGISTERED_PROVIDERS) {
                REGISTERED_PROVIDERS.add(BOUNCY_CASTLE);
            }
            return null;
        }
    }

    /* -------------------------------------------------------------------- */

    private interface BouncyCastleInputStreamLoader {
        static KeyPair loadKeyPair(String resourceKey, InputStream inputStream, FilePasswordProvider provider)
                throws IOException, GeneralSecurityException {
            try (PEMParser r = new PEMParser(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                Object o = r.readObject();

                JcaPEMKeyConverter pemConverter = new JcaPEMKeyConverter();
                pemConverter.setProvider(SecurityUtils.BOUNCY_CASTLE);
                if (o instanceof PEMEncryptedKeyPair) {
                    ValidateUtils.checkNotNull(provider, "No password provider for resource=%s", resourceKey);

                    String password = ValidateUtils.checkNotNullAndNotEmpty(provider.getPassword(resourceKey), "No password provided for resource=%s", resourceKey);
                    JcePEMDecryptorProviderBuilder decryptorBuilder = new JcePEMDecryptorProviderBuilder();
                    PEMDecryptorProvider pemDecryptor = decryptorBuilder.build(password.toCharArray());
                    o = ((PEMEncryptedKeyPair) o).decryptKeyPair(pemDecryptor);
                }

                if (o instanceof PEMKeyPair) {
                    return pemConverter.getKeyPair((PEMKeyPair) o);
                } else if (o instanceof KeyPair) {
                    return (KeyPair) o;
                } else {
                    throw new IOException("Failed to read " + resourceKey + " - unknown result object: " + o);
                }
            }
        }
    }

    /**
     * @param resourceKey An identifier of the key being loaded - used as
     *                    argument to the {@link FilePasswordProvider#getPassword(String)}
     *                    invocation
     * @param inputStream The {@link InputStream} for the <U>private</U> key
     * @param provider    A {@link FilePasswordProvider} - may be {@code null}
     *                    if the loaded key is <U>guaranteed</U> not to be encrypted
     * @return The loaded {@link KeyPair}
     * @throws IOException              If failed to read/parse the input stream
     * @throws GeneralSecurityException If failed to generate the keys - specifically,
     *                                  {@link NoSuchProviderException} is thrown also if {@link #isBouncyCastleRegistered()}
     *                                  is {@code false}
     */
    public static KeyPair loadKeyPairIdentity(String resourceKey, InputStream inputStream, FilePasswordProvider provider)
            throws IOException, GeneralSecurityException {
        if (!isBouncyCastleRegistered()) {
            throw new NoSuchProviderException("BouncyCastle not registered");
        }

        return BouncyCastleInputStreamLoader.loadKeyPair(resourceKey, inputStream, provider);
    }

    /* -------------------------------------------------------------------- */

    // use a separate class in order to avoid direct dependency
    private static final class BouncyCastleFileKeyPairProvider extends AbstractFileKeyPairProvider {
        private BouncyCastleFileKeyPairProvider() {
            ValidateUtils.checkTrue(isBouncyCastleRegistered(), "BouncyCastle not registered");
        }

        @Override
        protected KeyPair doLoadKey(String resourceKey, InputStream inputStream, FilePasswordProvider provider)
                throws IOException, GeneralSecurityException {
            return BouncyCastleInputStreamLoader.loadKeyPair(resourceKey, inputStream, provider);
        }
    }

    @SuppressWarnings("synthetic-access")
    public static AbstractFileKeyPairProvider createFileKeyPairProvider() {
        return new BouncyCastleFileKeyPairProvider();
    }

    /* -------------------------------------------------------------------- */

    private static final class BouncyCastleClassLoadableResourceKeyPairProvider extends AbstractClassLoadableResourceKeyPairProvider {
        private BouncyCastleClassLoadableResourceKeyPairProvider() {
            ValidateUtils.checkTrue(isBouncyCastleRegistered(), "BouncyCastle not registered");
        }

        @Override
        protected KeyPair doLoadKey(String resourceKey, InputStream inputStream, FilePasswordProvider provider)
                throws IOException, GeneralSecurityException {
            return BouncyCastleInputStreamLoader.loadKeyPair(resourceKey, inputStream, provider);
        }
    }

    @SuppressWarnings("synthetic-access")
    public static AbstractClassLoadableResourceKeyPairProvider createClassLoadableResourceKeyPairProvider() {
        return new BouncyCastleClassLoadableResourceKeyPairProvider();
    }

    /* -------------------------------------------------------------------- */

    private static final class BouncyCastleGeneratorHostKeyProvider extends AbstractGeneratorHostKeyProvider {
        private BouncyCastleGeneratorHostKeyProvider(Path path) {
            ValidateUtils.checkTrue(isBouncyCastleRegistered(), "BouncyCastle not registered");
            setPath(path);
        }

        @Override
        protected KeyPair doReadKeyPair(String resourceKey, InputStream inputStream) throws IOException, GeneralSecurityException {
            return BouncyCastleInputStreamLoader.loadKeyPair(resourceKey, inputStream, null);
        }

        @SuppressWarnings("deprecation")
        @Override
        protected void doWriteKeyPair(String resourceKey, KeyPair kp, OutputStream outputStream) throws IOException, GeneralSecurityException {
            try (org.bouncycastle.openssl.PEMWriter w =
                         new org.bouncycastle.openssl.PEMWriter(new OutputStreamWriter(outputStream, StandardCharsets.UTF_8))) {
                w.writeObject(kp);
                w.flush();
            }
        }
    }

    @SuppressWarnings("synthetic-access")
    public static AbstractGeneratorHostKeyProvider createGeneratorHostKeyProvider(Path path) {
        return new BouncyCastleGeneratorHostKeyProvider(path);
    }

    /* -------------------------------------------------------------------- */

    /**
     * Named factory for the BouncyCastle <code>Random</code>
     */
    public static final class BouncyCastleRandomFactory extends AbstractRandomFactory {
        public static final String NAME = "bouncycastle";
        private static final BouncyCastleRandomFactory INSTANCE = new BouncyCastleRandomFactory();

        public BouncyCastleRandomFactory() {
            super(NAME);
        }

        @Override
        public boolean isSupported() {
            return isBouncyCastleRegistered();
        }

        @Override
        public Random create() {
            return new BouncyCastleRandom();
        }
    }

    /**
     * BouncyCastle <code>Random</code>.
     * This pseudo random number generator uses the a very fast PRNG from BouncyCastle.
     * The JRE random will be used when creating a new generator to add some random
     * data to the seed.
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    public static final class BouncyCastleRandom extends AbstractRandom {
        public static final String NAME = BOUNCY_CASTLE;
        private final RandomGenerator random;

        BouncyCastleRandom() {
            ValidateUtils.checkTrue(isBouncyCastleRegistered(), "BouncyCastle not registered");
            this.random = new VMPCRandomGenerator();
            byte[] seed = new SecureRandom().generateSeed(8);
            this.random.addSeedMaterial(seed);
        }

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public void fill(byte[] bytes, int start, int len) {
            this.random.nextBytes(bytes, start, len);
        }

        /**
         * Returns a pseudo-random uniformly distributed {@code int}
         * in the half-open range [0, n).
         */
        @Override
        public int random(int n) {
            ValidateUtils.checkTrue(n > 0, "Limit must be positive: %d", n);
            if ((n & -n) == n) {
                return (int) ((n * (long) next(31)) >> 31);
            }

            int bits;
            int val;
            do {
                bits = next(31);
                val = bits % n;
            } while (bits - val + (n - 1) < 0);
            return val;
        }

        private int next(int numBits) {
            int bytes = (numBits + 7) / 8;
            byte next[] = new byte[bytes];
            int ret = 0;
            random.nextBytes(next);
            for (int i = 0; i < bytes; i++) {
                ret = (next[i] & 0xFF) | (ret << 8);
            }
            return ret >>> (bytes * 8 - numBits);
        }
    }

    /**
     * @return If {@link #isBouncyCastleRegistered()} then a {@link BouncyCastleRandomFactory}
     * instance, otherwise a {@link JceRandomFactory} one
     */
    @SuppressWarnings("synthetic-access")
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
    public static boolean isEDDSACurveSupported() {
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

    // see https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/HowToImplAProvider.html
    private static class EdDSASecurityProvider extends Provider {
        private static final long serialVersionUID = -6183277432144104981L;

        EdDSASecurityProvider() {
            super(EDDSA, 0.1, "net.i2p security provider wrapper");

            put("KeyPairGenerator." + EDDSA, "net.i2p.crypto.eddsa.KeyPairGenerator");
            put("KeyFactory." + EDDSA, "net.i2p.crypto.eddsa.KeyFactory");
            put("Signature." + EdDSANamedCurveTable.CURVE_ED25519_SHA512, "net.i2p.crypto.eddsa.EdDSAEngine");
        }

        private static boolean compareEDDSAPPublicKeys(PublicKey k1, PublicKey k2) {
            if ((k1 instanceof EdDSAPublicKey) && (k2 instanceof EdDSAPublicKey)) {
                if (Objects.equals(k1, k2)) {
                    return true;
                } else if (k1 == null || k2 == null) {
                    return false;   // both null is covered by Objects#equals
                }

                EdDSAPublicKey ed1 = (EdDSAPublicKey) k1;
                EdDSAPublicKey ed2 = (EdDSAPublicKey) k2;
                return Arrays.equals(ed1.getAbyte(), ed2.getAbyte())
                    && compareEDDSAKeyParams(ed1.getParams(), ed2.getParams());
            }

            return false;
        }

        private static boolean compareEDDSAPrivateKeys(PrivateKey k1, PrivateKey k2) {
            if (!isEDDSACurveSupported()) {
                return false;
            }

            if ((k1 instanceof EdDSAPrivateKey) && (k2 instanceof EdDSAPrivateKey)) {
                if (Objects.equals(k1, k2)) {
                    return true;
                } else if (k1 == null || k2 == null) {
                    return false;   // both null is covered by Objects#equals
                }

                EdDSAPrivateKey ed1 = (EdDSAPrivateKey) k1;
                EdDSAPrivateKey ed2 = (EdDSAPrivateKey) k2;
                return Arrays.equals(ed1.getSeed(), ed2.getSeed())
                    && compareEDDSAKeyParams(ed1.getParams(), ed2.getParams());
            }

            return false;
        }

        private static boolean compareEDDSAKeyParams(EdDSAParameterSpec s1, EdDSAParameterSpec s2) {
            if (Objects.equals(s1, s2)) {
                return true;
            } else if (s1 == null || s2 == null) {
                return false;   // both null is covered by Objects#equals
            } else {
                return Objects.equals(s1.getHashAlgorithm(), s2.getHashAlgorithm())
                    && Objects.equals(s1.getCurve(), s2.getCurve())
                    && Objects.equals(s1.getB(), s2.getB());
            }
        }

        private static PublicKey generateEDDSAPublicKey(byte[] seed) throws GeneralSecurityException {
            EdDSAParameterSpec params = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512);
            EdDSAPublicKeySpec keySpec = new EdDSAPublicKeySpec(seed, params);
            KeyFactory factory = SecurityUtils.getKeyFactory(EDDSA);
            return factory.generatePublic(keySpec);
        }

        private static <B extends Buffer> B putRawEDDSAPublicKey(B buffer, PublicKey key) {
            EdDSAPublicKey edKey = ValidateUtils.checkInstanceOf(key, EdDSAPublicKey.class, "Not an EDDSA public key: %s", key);
            byte[] seed = Ed25519PublicKeyDecoder.getSeedValue(edKey);
            ValidateUtils.checkNotNull(seed, "No seed extracted from key: %s", edKey.getA());
            buffer.putString(KeyPairProvider.SSH_ED25519);
            buffer.putBytes(seed);
            return buffer;
        }

        private static <B extends Buffer> B putEDDSAKeyPair(B buffer, PublicKey pubKey, PrivateKey prvKey) {
            ValidateUtils.checkInstanceOf(pubKey, EdDSAPublicKey.class, "Not an EDDSA public key: %s", pubKey);
            ValidateUtils.checkInstanceOf(prvKey, EdDSAPrivateKey.class, "Not an EDDSA private key: %s", prvKey);
            throw new UnsupportedOperationException("Full SSHD-440 implementation N/A");
        }
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
            if (java.security.Security.getProvider(EDDSA) == null) {
                logger.info("Trying to register " + EDDSA + " as a JCE provider");
                java.security.Security.addProvider(new EdDSASecurityProvider());
                KeyFactory.getInstance(EDDSA, EDDSA);
                logger.info("Registration succeeded");
            } else {
                logger.info(EDDSA + " already registered as a JCE provider");
            }

            synchronized (REGISTERED_PROVIDERS) {
                REGISTERED_PROVIDERS.add(EDDSA);
            }

            return null;
        }
    }

    /* -------------------------------------------------------------------- */

    private static final class Ed25519PublicKeyDecoder extends AbstractPublicKeyEntryDecoder<EdDSAPublicKey, EdDSAPrivateKey> {
        private static final Ed25519PublicKeyDecoder INSTANCE = new Ed25519PublicKeyDecoder();

        private Ed25519PublicKeyDecoder() {
            super(EdDSAPublicKey.class, EdDSAPrivateKey.class, Collections.unmodifiableList(Collections.singletonList(KeyPairProvider.SSH_ED25519)));
        }

        @Override
        public EdDSAPublicKey clonePublicKey(EdDSAPublicKey key) throws GeneralSecurityException {
            if (key == null) {
                return null;
            } else {
                return generatePublicKey(new EdDSAPublicKeySpec(key.getA(), key.getParams()));
            }
        }

        @Override
        public EdDSAPrivateKey clonePrivateKey(EdDSAPrivateKey key) throws GeneralSecurityException {
            if (key == null) {
                return null;
            } else {
                return generatePrivateKey(new EdDSAPrivateKeySpec(key.getSeed(), key.getParams()));
            }
        }

        @Override
        public KeyPairGenerator getKeyPairGenerator() throws GeneralSecurityException {
            return SecurityUtils.getKeyPairGenerator(EDDSA);
        }

        @Override
        public String encodePublicKey(OutputStream s, EdDSAPublicKey key) throws IOException {
            Objects.requireNonNull(key, "No public key provided");
            PublicKeyEntryDecoder.encodeString(s, KeyPairProvider.SSH_ED25519);
            byte[] seed = getSeedValue(key);
            PublicKeyEntryDecoder.writeRLEBytes(s, seed);
            return KeyPairProvider.SSH_ED25519;
        }

        @Override
        public KeyFactory getKeyFactoryInstance() throws GeneralSecurityException {
            return SecurityUtils.getKeyFactory(EDDSA);
        }

        @Override
        public EdDSAPublicKey decodePublicKey(String keyType, InputStream keyData) throws IOException, GeneralSecurityException {
            byte[] seed = PublicKeyEntryDecoder.readRLEBytes(keyData);
            return EdDSAPublicKey.class.cast(SecurityUtils.generateEDDSAPublicKey(keyType, seed));
        }

        public static byte[] getSeedValue(EdDSAPublicKey key) {
            // a bit of reverse-engineering on the EdDSAPublicKeySpec
            return (key == null) ? null : key.getAbyte();
        }

        private static EdDSAPublicKey fromPrivateKey(EdDSAPrivateKey prvKey) throws GeneralSecurityException {
            if (prvKey == null) {
                return null;
            }

            EdDSAPublicKeySpec keySpec = new EdDSAPublicKeySpec(prvKey.getSeed(), prvKey.getParams());
            KeyFactory factory = SecurityUtils.getKeyFactory(EDDSA);
            return EdDSAPublicKey.class.cast(factory.generatePublic(keySpec));
        }
    }

    @SuppressWarnings("synthetic-access")
    public static PublicKeyEntryDecoder<? extends PublicKey, ? extends PrivateKey> getEDDSAPublicKeyEntryDecoder() {
        if (!isEDDSACurveSupported()) {
            throw new UnsupportedOperationException(EDDSA + " provider N/A");
        }

        return Ed25519PublicKeyDecoder.INSTANCE;
    }

    /* -------------------------------------------------------------------- */

    private static final class SignatureEd25519 extends AbstractSignature {
        private SignatureEd25519() {
            super(EdDSANamedCurveTable.CURVE_ED25519_SHA512);
        }

        @Override
        public boolean verify(byte[] sig) throws Exception {
            byte[] data = sig;
            Pair<String, byte[]> encoding = extractEncodedSignature(data);
            if (encoding != null) {
                String keyType = encoding.getFirst();
                ValidateUtils.checkTrue(KeyPairProvider.SSH_ED25519.equals(keyType), "Mismatched key type: %s", keyType);
                data = encoding.getSecond();
            }

            return doVerify(data);
        }
    }

    @SuppressWarnings("synthetic-access")
    public static org.apache.sshd.common.signature.Signature getEDDSASigner() {
        if (isEDDSACurveSupported()) {
            return new SignatureEd25519();
        }

        throw new UnsupportedOperationException(EDDSA + " Signer not available");
    }

    /* -------------------------------------------------------------------- */

    public static int getEDDSAKeySize(Key key) {
        return (key instanceof EdDSAKey) ? 256 : -1;
    }

    public static Class<? extends PublicKey> getEDDSAPublicKeyType() {
        return isEDDSACurveSupported() ? EdDSAPublicKey.class : PublicKey.class;
    }

    public static Class<? extends PrivateKey> getEDDSAPrivateKeyType() {
        return isEDDSACurveSupported() ? EdDSAPrivateKey.class : PrivateKey.class;
    }

    @SuppressWarnings("synthetic-access")
    public static boolean compareEDDSAPPublicKeys(PublicKey k1, PublicKey k2) {
        return isEDDSACurveSupported() ? EdDSASecurityProvider.compareEDDSAPPublicKeys(k1, k2) : false;
    }

    @SuppressWarnings("synthetic-access")
    public static boolean compareEDDSAPrivateKeys(PrivateKey k1, PrivateKey k2) {
        return isEDDSACurveSupported() ? EdDSASecurityProvider.compareEDDSAPrivateKeys(k1, k2) : false;
    }

    /* -------------------------------------------------------------------- */

    @SuppressWarnings("synthetic-access")
    public static PublicKey generateEDDSAPublicKey(String keyType, byte[] seed) throws GeneralSecurityException {
        if (!KeyPairProvider.SSH_ED25519.equals(keyType)) {
            throw new InvalidKeyException("Unsupported key type: " + keyType);
        }

        if (!isEDDSACurveSupported()) {
            throw new NoSuchAlgorithmException(EDDSA + " provider not supported");
        }

        return EdDSASecurityProvider.generateEDDSAPublicKey(seed);
    }

    @SuppressWarnings("synthetic-access")
    public static <B extends Buffer> B putRawEDDSAPublicKey(B buffer, PublicKey key) {
        if (!isEDDSACurveSupported()) {
            throw new UnsupportedOperationException(EDDSA + " provider not supported");
        }

        return EdDSASecurityProvider.putRawEDDSAPublicKey(buffer, key);
    }

    public static <B extends Buffer> B putEDDSAKeyPair(B buffer, KeyPair kp) {
        return putEDDSAKeyPair(buffer, Objects.requireNonNull(kp, "No key pair").getPublic(), kp.getPrivate());
    }

    @SuppressWarnings("synthetic-access")
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

    public static synchronized KeyFactory getKeyFactory(String algorithm) throws GeneralSecurityException {
        register();

        String providerName = getDefaultProvider();
        if (EDDSA.equalsIgnoreCase(algorithm) && isEDDSACurveSupported()) {
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
        if (EDDSA.equalsIgnoreCase(algorithm) && isEDDSACurveSupported()) {
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
        if (EdDSANamedCurveTable.CURVE_ED25519_SHA512.equalsIgnoreCase(algorithm) && isEDDSACurveSupported()) {
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
