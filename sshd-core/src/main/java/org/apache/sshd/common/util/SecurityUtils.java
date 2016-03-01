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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.DHParameterSpec;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.AbstractClassLoadableResourceKeyPairProvider;
import org.apache.sshd.common.keyprovider.AbstractFileKeyPairProvider;
import org.apache.sshd.common.random.AbstractRandom;
import org.apache.sshd.common.random.AbstractRandomFactory;
import org.apache.sshd.common.random.JceRandomFactory;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.random.RandomFactory;
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
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class SecurityUtils {
    /**
     * Bouncycastle JCE provider name
     */
    public static final String BOUNCY_CASTLE = "BC";

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

    private static final AtomicInteger MAX_DHG_KEY_SIZE_HOLDER = new AtomicInteger(0);

    private static String securityProvider;
    private static Boolean registerBouncyCastle;
    private static boolean registrationDone;
    private static Boolean hasEcc;

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

    public static synchronized void setSecurityProvider(String securityProvider) {
        SecurityUtils.securityProvider = securityProvider;
        registrationDone = false;
    }

    public static synchronized void setRegisterBouncyCastle(boolean registerBouncyCastle) {
        SecurityUtils.registerBouncyCastle = registerBouncyCastle;
        registrationDone = false;
    }

    public static synchronized String getSecurityProvider() {
        register();
        return securityProvider;
    }

    public static synchronized boolean isBouncyCastleRegistered() {
        register();
        return BOUNCY_CASTLE.equals(securityProvider);
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

            if ((securityProvider == null) && ((registerBouncyCastle == null) || registerBouncyCastle)) {
                // Use an inner class to avoid a strong dependency from SshServer on BouncyCastle
                try {
                    new BouncyCastleRegistration().call();
                } catch (Throwable t) {
                    Logger logger = LoggerFactory.getLogger(SecurityUtils.class);
                    if (registerBouncyCastle == null) {
                        logger.info("BouncyCastle not registered, using the default JCE provider");
                    } else {
                        logger.error("Failed {} to register BouncyCastle as the defaut JCE provider: {}", t.getClass().getSimpleName(), t.getMessage());
                        throw new RuntimeException("Failed to register BouncyCastle as the defaut JCE provider", t);
                    }
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
            securityProvider = BOUNCY_CASTLE;
            return null;
        }
    }

    /* -------------------------------------------------------------------- */

    // TODO in JDK-8 make this an interface...
    private static class BouncyCastleInputStreamLoader {
        public static KeyPair loadKeyPair(String resourceKey, InputStream inputStream, FilePasswordProvider provider)
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

    //////////////////////////////////////////////////////////////////////////

    public static synchronized KeyFactory getKeyFactory(String algorithm) throws GeneralSecurityException {
        register();

        String providerName = getSecurityProvider();
        if (GenericUtils.isEmpty(providerName)) {
            return KeyFactory.getInstance(algorithm);
        } else {
            return KeyFactory.getInstance(algorithm, providerName);
        }
    }

    public static synchronized Cipher getCipher(String transformation) throws GeneralSecurityException {
        register();

        String providerName = getSecurityProvider();
        if (GenericUtils.isEmpty(providerName)) {
            return Cipher.getInstance(transformation);
        } else {
            return Cipher.getInstance(transformation, providerName);
        }
    }

    public static synchronized MessageDigest getMessageDigest(String algorithm) throws GeneralSecurityException {
        register();

        String providerName = getSecurityProvider();
        if (GenericUtils.isEmpty(providerName)) {
            return MessageDigest.getInstance(algorithm);
        } else {
            return MessageDigest.getInstance(algorithm, providerName);
        }
    }

    public static synchronized KeyPairGenerator getKeyPairGenerator(String algorithm) throws GeneralSecurityException {
        register();

        String providerName = getSecurityProvider();
        if (GenericUtils.isEmpty(providerName)) {
            return KeyPairGenerator.getInstance(algorithm);
        } else {
            return KeyPairGenerator.getInstance(algorithm, providerName);
        }
    }

    public static synchronized KeyAgreement getKeyAgreement(String algorithm) throws GeneralSecurityException {
        register();

        String providerName = getSecurityProvider();
        if (GenericUtils.isEmpty(providerName)) {
            return KeyAgreement.getInstance(algorithm);
        } else {
            return KeyAgreement.getInstance(algorithm, providerName);
        }
    }

    public static synchronized Mac getMac(String algorithm) throws GeneralSecurityException {
        register();

        String providerName = getSecurityProvider();
        if (GenericUtils.isEmpty(providerName)) {
            return Mac.getInstance(algorithm);
        } else {
            return Mac.getInstance(algorithm, providerName);
        }
    }

    public static synchronized Signature getSignature(String algorithm) throws GeneralSecurityException {
        register();

        String providerName = getSecurityProvider();
        if (GenericUtils.isEmpty(providerName)) {
            return Signature.getInstance(algorithm);
        } else {
            return Signature.getInstance(algorithm, providerName);
        }
    }

    public static synchronized CertificateFactory getCertificateFactory(String type) throws GeneralSecurityException {
        register();

        String providerName = getSecurityProvider();
        if (GenericUtils.isEmpty(providerName)) {
            return CertificateFactory.getInstance(type);
        } else {
            return CertificateFactory.getInstance(type, providerName);
        }
    }
}
