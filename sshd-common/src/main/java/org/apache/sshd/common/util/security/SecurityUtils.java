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
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.DHParameterSpec;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.PropertyResolverUtils;
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
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.security.bouncycastle.BouncyCastleGeneratorHostKeyProvider;
import org.apache.sshd.common.util.security.bouncycastle.BouncyCastleKeyPairResourceParser;
import org.apache.sshd.common.util.security.bouncycastle.BouncyCastleRandomFactory;
import org.apache.sshd.common.util.security.eddsa.EdDSASecurityProviderUtils;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.keyprovider.AbstractGeneratorHostKeyProvider;
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
     * EDDSA support - should match {@code EdDSAKey.KEY_ALGORITHM}
     */
    public static final String EDDSA = "EdDSA";

    // A copy-paste from the original, but we don't want to drag the classes into the classpath
    // See EdDSAEngine.SIGNATURE_ALGORITHM
    public static final String CURVE_ED25519_SHA512 = "NONEwithEdDSA";

    /**
     * System property used to configure the value for the minimum supported Diffie-Hellman Group Exchange key size. If
     * not set, then an internal auto-discovery mechanism is employed. If set to negative value then Diffie-Hellman
     * Group Exchange is disabled. If set to a negative value then Diffie-Hellman Group Exchange is disabled
     */
    public static final String MIN_DHGEX_KEY_SIZE_PROP = "org.apache.sshd.minDHGexKeySize";

    /**
     * System property used to configure the value for the maximum supported Diffie-Hellman Group Exchange key size. If
     * not set, then an internal auto-discovery mechanism is employed. If set to negative value then Diffie-Hellman
     * Group Exchange is disabled. If set to a negative value then Diffie-Hellman Group Exchange is disabled
     */
    public static final String MAX_DHGEX_KEY_SIZE_PROP = "org.apache.sshd.maxDHGexKeySize";

    /**
     * The min. key size value used for testing whether Diffie-Hellman Group Exchange is supported or not. According to
     * <A HREF="https://tools.ietf.org/html/rfc4419">RFC 4419</A> section 3: &quot;Servers and clients SHOULD support
     * groups with a modulus length of k bits, where 1024 <= k <= 8192&quot;. </code>
     *
     * <B>Note: this has been amended by <A HREF="https://tools.ietf.org/html/rfc8270">RFC 8270</A>
     */
    public static final int MIN_DHGEX_KEY_SIZE = 2048;
    public static final int PREFERRED_DHGEX_KEY_SIZE = 4096;
    public static final int MAX_DHGEX_KEY_SIZE = 8192;

    /**
     * Comma separated list of fully qualified {@link SecurityProviderRegistrar}s to automatically register
     */
    public static final String SECURITY_PROVIDER_REGISTRARS = "org.apache.sshd.security.registrars";
    public static final List<String> DEFAULT_SECURITY_PROVIDER_REGISTRARS = Collections.unmodifiableList(
            Arrays.asList(
                    "org.apache.sshd.common.util.security.bouncycastle.BouncyCastleSecurityProviderRegistrar",
                    "org.apache.sshd.common.util.security.eddsa.EdDSASecurityProviderRegistrar"));

    /**
     * System property used to control whether to automatically register the {@code Bouncyastle} JCE provider
     *
     * @deprecated Please use &quot;org.apache.sshd.security.provider.BC.enabled&quot;
     */
    @Deprecated
    public static final String REGISTER_BOUNCY_CASTLE_PROP = "org.apache.sshd.registerBouncyCastle";

    /**
     * System property used to control whether Elliptic Curves are supported or not. If not set then the support is
     * auto-detected. <B>Note:</B> if set to {@code true} it is up to the user to make sure that indeed there is a
     * provider for them
     */
    public static final String ECC_SUPPORTED_PROP = "org.apache.sshd.eccSupport";

    /**
     * System property used to decide whether EDDSA curves are supported or not (in addition or even in spite of
     * {@link #isEDDSACurveSupported()}). If not set or set to {@code true}, then the existence of the optional support
     * classes determines the support.
     *
     * @deprecated Please use &quot;org.apache.sshd.security.provider.EdDSA.enabled&qupt;
     */
    @Deprecated
    public static final String EDDSA_SUPPORTED_PROP = "org.apache.sshd.eddsaSupport";

    public static final String PROP_DEFAULT_SECURITY_PROVIDER = "org.apache.sshd.security.defaultProvider";

    private static final AtomicInteger MIN_DHG_KEY_SIZE_HOLDER = new AtomicInteger(0);
    private static final AtomicInteger MAX_DHG_KEY_SIZE_HOLDER = new AtomicInteger(0);

    /*
     * NOTE: we use a LinkedHashMap in order to preserve registration order in case several providers support the same
     * security entity
     */
    private static final Map<String, SecurityProviderRegistrar> REGISTERED_PROVIDERS = new LinkedHashMap<>();
    private static final AtomicReference<KeyPairResourceParser> KEYPAIRS_PARSER_HODLER = new AtomicReference<>();
    // If an entry already exists for the named provider, then it overrides its SecurityProviderRegistrar#isEnabled()
    private static final Set<String> APRIORI_DISABLED_PROVIDERS = new TreeSet<>();
    private static final AtomicBoolean REGISTRATION_STATE_HOLDER = new AtomicBoolean(false);
    private static final Map<Class<?>, Map<String, SecurityEntityFactory<?>>> SECURITY_ENTITY_FACTORIES = new HashMap<>();

    private static final AtomicReference<SecurityProviderChoice> DEFAULT_PROVIDER_HOLDER = new AtomicReference<>();

    private static Boolean hasEcc;

    private SecurityUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * @param  name The provider's name - never {@code null}/empty
     * @return      {@code true} if the provider is marked as disabled a-priori
     * @see         #setAPrioriDisabledProvider(String, boolean)
     */
    public static boolean isAPrioriDisabledProvider(String name) {
        ValidateUtils.checkNotNullAndNotEmpty(name, "No provider name specified");
        synchronized (APRIORI_DISABLED_PROVIDERS) {
            return APRIORI_DISABLED_PROVIDERS.contains(name);
        }
    }

    /**
     * Marks a provider's registrar as &quot;a-priori&quot; <U>programatically</U> so that when its
     * {@link SecurityProviderRegistrar#isEnabled()} is eventually consulted it will return {@code false} regardless of
     * the configured value for the specific provider registrar instance. <B>Note:</B> has no effect if the provider has
     * already been registered.
     *
     * @param name     The provider's name - never {@code null}/empty
     * @param disabled {@code true} whether to disable it a-priori
     * @see            #isAPrioriDisabledProvider(String)
     */
    public static void setAPrioriDisabledProvider(String name, boolean disabled) {
        ValidateUtils.checkNotNullAndNotEmpty(name, "No provider name specified");
        synchronized (APRIORI_DISABLED_PROVIDERS) {
            if (disabled) {
                APRIORI_DISABLED_PROVIDERS.add(name);
            } else {
                APRIORI_DISABLED_PROVIDERS.remove(name);
            }
        }
    }

    /**
     * @return A <U>copy</U> if the current a-priori disabled providers names
     */
    public static Set<String> getAPrioriDisabledProviders() {
        synchronized (APRIORI_DISABLED_PROVIDERS) {
            return new TreeSet<>(APRIORI_DISABLED_PROVIDERS);
        }
    }

    /**
     * @return {@code true} if Elliptic Curve Cryptography is supported
     * @see    #ECC_SUPPORTED_PROP
     */
    public static boolean isECCSupported() {
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
     * @see    #getMinDHGroupExchangeKeySize()
     * @see    #getMaxDHGroupExchangeKeySize()
     */
    public static boolean isDHGroupExchangeSupported() {
        int maxSize = getMaxDHGroupExchangeKeySize();
        int minSize = getMinDHGroupExchangeKeySize();
        return (minSize > 0) && (maxSize > 0) && (minSize <= maxSize);
    }

    /**
     * @param  keySize The expected key size
     * @return         {@code true} if Oakely Diffie-Hellman Group Exchange is supported for the specified key size
     * @see            #isDHGroupExchangeSupported()
     * @see            #getMaxDHGroupExchangeKeySize()
     */
    public static boolean isDHOakelyGroupSupported(int keySize) {
        return isDHGroupExchangeSupported()
                && (getMaxDHGroupExchangeKeySize() >= keySize);
    }

    /**
     * @return The minimum supported Diffie-Hellman Group Exchange key size, or non-positive if not supported
     */
    public static int getMinDHGroupExchangeKeySize() {
        return resolveDHGEXKeySizeValue(MIN_DHG_KEY_SIZE_HOLDER, MIN_DHGEX_KEY_SIZE_PROP, MIN_DHGEX_KEY_SIZE);
    }

    /**
     * Set programmatically the reported value for {@link #getMinDHGroupExchangeKeySize()}
     *
     * @param keySize The reported key size - if zero, then it will be auto-detected, if negative then DH group exchange
     *                will be disabled
     */
    public static void setMinDHGroupExchangeKeySize(int keySize) {
        synchronized (MIN_DHG_KEY_SIZE_HOLDER) {
            MIN_DHG_KEY_SIZE_HOLDER.set(keySize);
        }
    }

    /**
     * @return The maximum supported Diffie-Hellman Group Exchange key size, or non-positive if not supported
     */
    public static int getMaxDHGroupExchangeKeySize() {
        return resolveDHGEXKeySizeValue(MAX_DHG_KEY_SIZE_HOLDER, MAX_DHGEX_KEY_SIZE_PROP, MAX_DHGEX_KEY_SIZE);
    }

    /**
     * Set programmatically the reported value for {@link #getMaxDHGroupExchangeKeySize()}
     *
     * @param keySize The reported key size - if zero, then it will be auto-detected, if negative then DH group exchange
     *                will be disabled
     */
    public static void setMaxDHGroupExchangeKeySize(int keySize) {
        synchronized (MAX_DHG_KEY_SIZE_HOLDER) {
            MAX_DHG_KEY_SIZE_HOLDER.set(keySize);
        }
    }

    private static int resolveDHGEXKeySizeValue(
            AtomicInteger holder, String propName, int maxKeySize) {
        int maxSupportedKeySize;
        synchronized (holder) {
            maxSupportedKeySize = holder.get();
            if (maxSupportedKeySize != 0) { // 1st time we are called ?
                return maxSupportedKeySize;
            }

            String propValue = System.getProperty(propName);
            if (GenericUtils.isEmpty(propValue)) {
                maxSupportedKeySize = -1;
                // Go down from max. to min. to ensure we stop at 1st maximum value success
                for (int testKeySize = maxKeySize; testKeySize >= MIN_DHGEX_KEY_SIZE; testKeySize -= 1024) {
                    if (isDHGroupExchangeSupported(testKeySize)) {
                        maxSupportedKeySize = testKeySize;
                        break;
                    }
                }
            } else {
                Logger logger = LoggerFactory.getLogger(SecurityUtils.class);
                logger.info("Override DH group exchange key size via {}: {}", propName, propValue);
                maxSupportedKeySize = Integer.parseInt(propValue);
                // negative is OK - means user wants to disable DH group exchange
                ValidateUtils.checkTrue(maxSupportedKeySize != 0,
                        "Configured " + propName + " value must be non-zero: %d", maxSupportedKeySize);
            }

            holder.set(maxSupportedKeySize);
        }

        return maxSupportedKeySize;
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

    public static SecurityProviderChoice getDefaultProviderChoice() {
        SecurityProviderChoice choice;
        synchronized (DEFAULT_PROVIDER_HOLDER) {
            choice = DEFAULT_PROVIDER_HOLDER.get();
            if (choice != null) {
                return choice;
            }

            String name = System.getProperty(PROP_DEFAULT_SECURITY_PROVIDER);
            choice = (GenericUtils.isEmpty(name) || PropertyResolverUtils.isNoneValue(name))
                    ? SecurityProviderChoice.EMPTY
                    : SecurityProviderChoice.toSecurityProviderChoice(name);
            DEFAULT_PROVIDER_HOLDER.set(choice);
        }

        return choice;
    }

    public static void setDefaultProviderChoice(SecurityProviderChoice choice) {
        DEFAULT_PROVIDER_HOLDER.set(choice);
    }

    /**
     * @return A <U>copy</U> of the currently registered security providers
     */
    public static Set<String> getRegisteredProviders() {
        // returns a COPY of the providers in order to avoid modifications
        synchronized (REGISTERED_PROVIDERS) {
            return new TreeSet<>(REGISTERED_PROVIDERS.keySet());
        }
    }

    public static boolean isBouncyCastleRegistered() {
        register();
        return isProviderRegistered(BOUNCY_CASTLE);
    }

    public static boolean isProviderRegistered(String provider) {
        return getRegisteredProvider(provider) != null;
    }

    public static SecurityProviderRegistrar getRegisteredProvider(String provider) {
        ValidateUtils.checkNotNullAndNotEmpty(provider, "No provider name specified");
        synchronized (REGISTERED_PROVIDERS) {
            return REGISTERED_PROVIDERS.get(provider);
        }
    }

    public static boolean isRegistrationCompleted() {
        return REGISTRATION_STATE_HOLDER.get();
    }

    private static void register() {
        synchronized (REGISTRATION_STATE_HOLDER) {
            if (REGISTRATION_STATE_HOLDER.get()) {
                return;
            }

            String regsList = System.getProperty(SECURITY_PROVIDER_REGISTRARS,
                    GenericUtils.join(DEFAULT_SECURITY_PROVIDER_REGISTRARS, ','));
            boolean bouncyCastleRegistered = false;
            if ((GenericUtils.length(regsList) > 0) && (!PropertyResolverUtils.isNoneValue(regsList))) {
                String[] classes = GenericUtils.split(regsList, ',');
                Logger logger = LoggerFactory.getLogger(SecurityUtils.class);
                boolean debugEnabled = logger.isDebugEnabled();
                for (String registrarClass : classes) {
                    SecurityProviderRegistrar r;
                    try {
                        r = ThreadUtils.createDefaultInstance(SecurityUtils.class, SecurityProviderRegistrar.class,
                                registrarClass);
                    } catch (ReflectiveOperationException t) {
                        Throwable e = GenericUtils.peelException(t);
                        logger.error("Failed ({}) to create default {} registrar instance: {}",
                                e.getClass().getSimpleName(), registrarClass, e.getMessage());
                        if (e instanceof RuntimeException) {
                            throw (RuntimeException) e;
                        } else if (e instanceof Error) {
                            throw (Error) e;
                        } else {
                            throw new RuntimeException(e);
                        }
                    }

                    String name = r.getName();
                    SecurityProviderRegistrar registeredInstance = registerSecurityProvider(r);
                    if (registeredInstance == null) {
                        if (debugEnabled) {
                            logger.debug("register({}) not registered - enabled={}, supported={}",
                                    name, r.isEnabled(), r.isSupported());
                        }
                        continue; // provider not registered - e.g., disabled, not supported
                    }

                    if (BOUNCY_CASTLE.equalsIgnoreCase(name)) {
                        bouncyCastleRegistered = true;
                    }
                }
            }

            SecurityProviderChoice choice = getDefaultProviderChoice();
            if (((choice == null) || (choice == SecurityProviderChoice.EMPTY)) && bouncyCastleRegistered) {
                setDefaultProviderChoice(SecurityProviderChoice.toSecurityProviderChoice(BOUNCY_CASTLE));
            }

            REGISTRATION_STATE_HOLDER.set(true);
        }
    }

    /**
     * @param  registrar The registrar instance to register
     * @return           The registered instance - may be different than required if already registered. Returns
     *                   {@code null} if not already registered and not enabled or not supported registrar.
     */
    public static SecurityProviderRegistrar registerSecurityProvider(SecurityProviderRegistrar registrar) {
        Objects.requireNonNull(registrar, "No registrar instance to register");
        String name = registrar.getName();
        SecurityProviderRegistrar registeredInstance = getRegisteredProvider(name);
        if ((registeredInstance == null) && registrar.isEnabled() && registrar.isSupported()) {
            try {
                SecurityProviderRegistrar.registerSecurityProvider(registrar);
                synchronized (REGISTERED_PROVIDERS) {
                    REGISTERED_PROVIDERS.put(name, registrar);
                }

                return registrar;
            } catch (Throwable t) {
                Logger logger = LoggerFactory.getLogger(SecurityUtils.class);
                logger.error("Failed {} to register {} as a JCE provider: {}",
                        t.getClass().getSimpleName(), name, t.getMessage());
                throw new RuntimeException("Failed to register " + name + " as a JCE provider", t);
            }
        }

        return registeredInstance;
    }

    ///////////////// Bouncycastle specific implementations //////////////////

    /* -------------------------------------------------------------------- */

    /**
     * @param  session                  The {@link SessionContext} for invoking this load command - may be {@code null}
     *                                  if not invoked within a session context (e.g., offline tool).
     * @param  resourceKey              An identifier of the key being loaded - used as argument to the
     *                                  {@code FilePasswordProvider#getPassword} invocation
     * @param  inputStream              The {@link InputStream} for the <U>private</U> key
     * @param  provider                 A {@link FilePasswordProvider} - may be {@code null} if the loaded key is
     *                                  <U>guaranteed</U> not to be encrypted
     * @return                          The loaded {@link KeyPair}-s - or {@code null} if none loaded
     * @throws IOException              If failed to read/parse the input stream
     * @throws GeneralSecurityException If failed to generate the keys
     */
    public static Iterable<KeyPair> loadKeyPairIdentities(
            SessionContext session, NamedResource resourceKey, InputStream inputStream, FilePasswordProvider provider)
            throws IOException, GeneralSecurityException {
        KeyPairResourceParser parser = getKeyPairResourceParser();
        if (parser == null) {
            throw new NoSuchProviderException("No registered key-pair resource parser");
        }

        Collection<KeyPair> ids = parser.loadKeyPairs(session, resourceKey, provider, inputStream);
        int numLoaded = GenericUtils.size(ids);
        if (numLoaded <= 0) {
            return null;
        }

        return ids;
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
     * @return If {@link #isBouncyCastleRegistered()} then a {@link BouncyCastleRandomFactory} instance, otherwise a
     *         {@link JceRandomFactory} one
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
    public static boolean isEDDSACurveSupported() {
        register();

        SecurityProviderRegistrar r = getRegisteredProvider(EDDSA);
        return (r != null) && r.isEnabled() && r.isSupported();
    }

    /* -------------------------------------------------------------------- */

    public static PublicKeyEntryDecoder<? extends PublicKey, ? extends PrivateKey> getEDDSAPublicKeyEntryDecoder() {
        if (!isEDDSACurveSupported()) {
            throw new UnsupportedOperationException(EDDSA + " provider N/A");
        }

        return EdDSASecurityProviderUtils.getEDDSAPublicKeyEntryDecoder();
    }

    public static PrivateKeyEntryDecoder<? extends PublicKey, ? extends PrivateKey> getOpenSSHEDDSAPrivateKeyEntryDecoder() {
        if (!isEDDSACurveSupported()) {
            throw new UnsupportedOperationException(EDDSA + " provider N/A");
        }

        return EdDSASecurityProviderUtils.getOpenSSHEDDSAPrivateKeyEntryDecoder();
    }

    public static org.apache.sshd.common.signature.Signature getEDDSASigner() {
        if (isEDDSACurveSupported()) {
            return EdDSASecurityProviderUtils.getEDDSASignature();
        }

        throw new UnsupportedOperationException(EDDSA + " Signer not available");
    }

    public static int getEDDSAKeySize(Key key) {
        return EdDSASecurityProviderUtils.getEDDSAKeySize(key);
    }

    public static Class<? extends PublicKey> getEDDSAPublicKeyType() {
        return isEDDSACurveSupported() ? EdDSASecurityProviderUtils.getEDDSAPublicKeyType() : PublicKey.class;
    }

    public static Class<? extends PrivateKey> getEDDSAPrivateKeyType() {
        return isEDDSACurveSupported() ? EdDSASecurityProviderUtils.getEDDSAPrivateKeyType() : PrivateKey.class;
    }

    public static boolean compareEDDSAPPublicKeys(PublicKey k1, PublicKey k2) {
        return isEDDSACurveSupported() ? EdDSASecurityProviderUtils.compareEDDSAPPublicKeys(k1, k2) : false;
    }

    public static boolean compareEDDSAPrivateKeys(PrivateKey k1, PrivateKey k2) {
        return isEDDSACurveSupported() ? EdDSASecurityProviderUtils.compareEDDSAPrivateKeys(k1, k2) : false;
    }

    public static PublicKey recoverEDDSAPublicKey(PrivateKey key) throws GeneralSecurityException {
        if (!isEDDSACurveSupported()) {
            throw new NoSuchAlgorithmException(EDDSA + " provider not supported");
        }

        return EdDSASecurityProviderUtils.recoverEDDSAPublicKey(key);
    }

    public static PublicKey generateEDDSAPublicKey(String keyType, byte[] seed) throws GeneralSecurityException {
        if (!KeyPairProvider.SSH_ED25519.equals(keyType)) {
            throw new InvalidKeyException("Unsupported key type: " + keyType);
        }

        if (!isEDDSACurveSupported()) {
            throw new NoSuchAlgorithmException(EDDSA + " provider not supported");
        }

        return EdDSASecurityProviderUtils.generateEDDSAPublicKey(seed);
    }

    public static <B extends Buffer> B putRawEDDSAPublicKey(B buffer, PublicKey key) {
        if (!isEDDSACurveSupported()) {
            throw new UnsupportedOperationException(EDDSA + " provider not supported");
        }

        return EdDSASecurityProviderUtils.putRawEDDSAPublicKey(buffer, key);
    }

    public static <B extends Buffer> B putEDDSAKeyPair(B buffer, KeyPair kp) {
        return putEDDSAKeyPair(buffer, Objects.requireNonNull(kp, "No key pair").getPublic(), kp.getPrivate());
    }

    public static <B extends Buffer> B putEDDSAKeyPair(B buffer, PublicKey pubKey, PrivateKey prvKey) {
        if (!isEDDSACurveSupported()) {
            throw new UnsupportedOperationException(EDDSA + " provider not supported");
        }

        return EdDSASecurityProviderUtils.putEDDSAKeyPair(buffer, pubKey, prvKey);
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
     * @param parser The system-wide {@code KeyPairResourceParser} to use. If set to {@code null}, then the default
     *               parser will be re-constructed on next call to {@link #getKeyPairResourceParser()}
     */
    public static void setKeyPairResourceParser(KeyPairResourceParser parser) {
        synchronized (KEYPAIRS_PARSER_HODLER) {
            KEYPAIRS_PARSER_HODLER.set(parser);
        }
    }

    //////////////////////////// Security entities factories /////////////////////////////

    @SuppressWarnings("unchecked")
    public static <T> SecurityEntityFactory<T> resolveSecurityEntityFactory(
            Class<T> entityType, String algorithm, Predicate<? super SecurityProviderRegistrar> entitySelector) {
        Map<String, SecurityEntityFactory<?>> factoriesMap;
        synchronized (SECURITY_ENTITY_FACTORIES) {
            factoriesMap = SECURITY_ENTITY_FACTORIES.computeIfAbsent(
                    entityType, k -> new TreeMap<>(String.CASE_INSENSITIVE_ORDER));
        }

        String effectiveName = SecurityProviderRegistrar.getEffectiveSecurityEntityName(entityType, algorithm);
        SecurityEntityFactory<?> factoryEntry;
        synchronized (factoriesMap) {
            factoryEntry = factoriesMap.computeIfAbsent(
                    effectiveName, k -> createSecurityEntityFactory(entityType, entitySelector));
        }

        return (SecurityEntityFactory<T>) factoryEntry;
    }

    public static <T> SecurityEntityFactory<T> createSecurityEntityFactory(
            Class<T> entityType, Predicate<? super SecurityProviderRegistrar> entitySelector) {
        register();

        SecurityProviderRegistrar registrar;
        synchronized (REGISTERED_PROVIDERS) {
            registrar = SecurityProviderRegistrar.findSecurityProviderRegistrarBySecurityEntity(
                    entitySelector, REGISTERED_PROVIDERS.values());
        }

        try {
            return SecurityEntityFactory.toFactory(entityType, registrar, getDefaultProviderChoice());
        } catch (ReflectiveOperationException t) {
            Throwable e = GenericUtils.peelException(t);
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else if (e instanceof Error) {
                throw (Error) e;
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    public static KeyFactory getKeyFactory(String algorithm) throws GeneralSecurityException {
        SecurityEntityFactory<KeyFactory> factory
                = resolveSecurityEntityFactory(KeyFactory.class, algorithm, r -> r.isKeyFactorySupported(algorithm));
        return factory.getInstance(algorithm);
    }

    public static Cipher getCipher(String transformation) throws GeneralSecurityException {
        SecurityEntityFactory<Cipher> factory
                = resolveSecurityEntityFactory(Cipher.class, transformation, r -> r.isCipherSupported(transformation));
        return factory.getInstance(transformation);
    }

    public static MessageDigest getMessageDigest(String algorithm) throws GeneralSecurityException {
        SecurityEntityFactory<MessageDigest> factory
                = resolveSecurityEntityFactory(MessageDigest.class, algorithm, r -> r.isMessageDigestSupported(algorithm));
        return factory.getInstance(algorithm);
    }

    public static KeyPairGenerator getKeyPairGenerator(String algorithm) throws GeneralSecurityException {
        SecurityEntityFactory<KeyPairGenerator> factory = resolveSecurityEntityFactory(KeyPairGenerator.class, algorithm,
                r -> r.isKeyPairGeneratorSupported(algorithm));
        return factory.getInstance(algorithm);
    }

    public static KeyAgreement getKeyAgreement(String algorithm) throws GeneralSecurityException {
        SecurityEntityFactory<KeyAgreement> factory
                = resolveSecurityEntityFactory(KeyAgreement.class, algorithm, r -> r.isKeyAgreementSupported(algorithm));
        return factory.getInstance(algorithm);
    }

    public static Mac getMac(String algorithm) throws GeneralSecurityException {
        SecurityEntityFactory<Mac> factory
                = resolveSecurityEntityFactory(Mac.class, algorithm, r -> r.isMacSupported(algorithm));
        return factory.getInstance(algorithm);
    }

    public static Signature getSignature(String algorithm) throws GeneralSecurityException {
        SecurityEntityFactory<Signature> factory
                = resolveSecurityEntityFactory(Signature.class, algorithm, r -> r.isSignatureSupported(algorithm));
        return factory.getInstance(algorithm);
    }

    public static CertificateFactory getCertificateFactory(String type) throws GeneralSecurityException {
        SecurityEntityFactory<CertificateFactory> factory
                = resolveSecurityEntityFactory(CertificateFactory.class, type, r -> r.isCertificateFactorySupported(type));
        return factory.getInstance(type);
    }
}
