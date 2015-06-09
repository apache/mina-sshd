/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.config.keys;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * Utility class for keys
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class KeyUtils {
    private static final Map<String,PublicKeyEntryDecoder<?,?>> byKeyTypeDecodersMap =
            new TreeMap<String, PublicKeyEntryDecoder<?,?>>(String.CASE_INSENSITIVE_ORDER);
    private static final Map<Class<?>,PublicKeyEntryDecoder<?,?>> byKeyClassDecodersMap =
            new HashMap<Class<?>, PublicKeyEntryDecoder<?,?>>();

    static {
        registerPublicKeyEntryDecoder(RSAPublicKeyDecoder.INSTANCE);
        registerPublicKeyEntryDecoder(DSSPublicKeyEntryDecoder.INSTANCE);
        registerPublicKeyEntryDecoder(ECDSAPublicKeyEntryDecoder.INSTANCE);
    }

    private KeyUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * @param keyType The key type - {@code OpenSSH} name - e.g., {@code ssh-rsa, ssh-dss}
     * @param keySize The key size (in bits)
     * @return A {@link KeyPair} of the specified type and size
     * @throws GeneralSecurityException If failed to generate the key pair
     * @see #getPublicKeyEntryDecoder(String)
     * @see PublicKeyEntryDecoder#generateKeyPair(int)
     */
    public static KeyPair generateKeyPair(String keyType, int keySize) throws GeneralSecurityException {
        PublicKeyEntryDecoder<?,?> decoder = getPublicKeyEntryDecoder(keyType);
        if (decoder == null) {
            throw new InvalidKeySpecException("No decoder for key type=" + keyType);
        }
        
        return decoder.generateKeyPair(keySize);
    }

    /**
     * Performs a deep-clone of the original {@link KeyPair} - i.e., creates
     * <U>new</U> public/private keys that are clones of the original one
     * @param keyType The key type - {@code OpenSSH} name - e.g., {@code ssh-rsa, ssh-dss}
     * @param kp The {@link KeyPair} to clone - ignored if {@code null}
     * @return The cloned instance
     * @throws GeneralSecurityException If failed to clone the pair
     */
    public static KeyPair cloneKeyPair(String keyType, KeyPair kp) throws GeneralSecurityException {
        PublicKeyEntryDecoder<?,?> decoder = getPublicKeyEntryDecoder(keyType);
        if (decoder == null) {
            throw new InvalidKeySpecException("No decoder for key type=" + keyType);
        }

        return decoder.cloneKeyPair(kp);
    }

    /**
     * @param decoder The decoder to register
     * @throws IllegalArgumentException if no decoder or not key type or no
     * supported names for the decoder
     * @see PublicKeyEntryDecoder#getPublicKeyType()
     * @see PublicKeyEntryDecoder#getSupportedTypeNames()
     */
    public static void registerPublicKeyEntryDecoder(PublicKeyEntryDecoder<?,?> decoder) {
        ValidateUtils.checkNotNull(decoder, "No decoder specified", GenericUtils.EMPTY_OBJECT_ARRAY);

        Class<?> pubType = ValidateUtils.checkNotNull(decoder.getPublicKeyType(), "No public key type declared", GenericUtils.EMPTY_OBJECT_ARRAY);
        Class<?> prvType = ValidateUtils.checkNotNull(decoder.getPrivateKeyType(), "No private key type declared", GenericUtils.EMPTY_OBJECT_ARRAY);
        synchronized(byKeyClassDecodersMap) {
            byKeyClassDecodersMap.put(pubType, decoder);
            byKeyClassDecodersMap.put(prvType, decoder);
        }

        Collection<String> names = ValidateUtils.checkNotNullAndNotEmpty(decoder.getSupportedTypeNames(), "No supported key type", GenericUtils.EMPTY_OBJECT_ARRAY);
        synchronized(byKeyTypeDecodersMap) {
            for (String n : names) {
                PublicKeyEntryDecoder<?,?>  prev = byKeyTypeDecodersMap.put(n, decoder);
                if (prev != null) {
                    continue;   // debug breakpoint
                }
            }
        }
    }

    /**
     * @param keyType The {@code OpenSSH} key type string -  e.g., {@code ssh-rsa, ssh-dss}
     * - ignored if {@code null}/empty
     * @return The registered {@link PublicKeyEntryDecoder} or {code null} if not found
     */
    public static PublicKeyEntryDecoder<?,?> getPublicKeyEntryDecoder(String keyType) {
        if (GenericUtils.isEmpty(keyType)) {
            return null;
        }
        
        synchronized(byKeyTypeDecodersMap) {
            return byKeyTypeDecodersMap.get(keyType);
        }
    }
    
    /**
     * @param key The {@link Key} (public or private) - ignored if {@code null}
     * @return The registered {@link PublicKeyEntryDecoder} for this key or {code null} if no match found
     * @see #getPublicKeyEntryDecoder(Class)
     */
    public static PublicKeyEntryDecoder<?,?> getPublicKeyEntryDecoder(Key key) {
        if (key == null) {
            return null;
        } else {
            return getPublicKeyEntryDecoder(key.getClass());
        }
    }

    /**
     * @param keyType The key {@link Class} - ignored if {@code null} or not a {@link Key}
     * compatible type
     * @return The registered {@link PublicKeyEntryDecoder} or {code null} if no match found
     */
    public static PublicKeyEntryDecoder<?,?> getPublicKeyEntryDecoder(Class<?> keyType) {
        if ((keyType == null) || (!Key.class.isAssignableFrom(keyType))) {
            return null;
        }
        
        synchronized(byKeyTypeDecodersMap) {
            {
                PublicKeyEntryDecoder<?,?>  decoder=byKeyClassDecodersMap.get(keyType);
                if (decoder != null) {
                    return decoder;
                }
            }
            
            // in case it is a derived class
            for (PublicKeyEntryDecoder<?,?> decoder : byKeyClassDecodersMap.values()) {
                Class<?> pubType = decoder.getPublicKeyType(), prvType = decoder.getPrivateKeyType();
                if (pubType.isAssignableFrom(keyType) || prvType.isAssignableFrom(keyType)) {
                    return decoder;
                }
            }
        }
        
        return null;
    }

    /**
     * Retrieve the public key fingerprint
     *
     * @param key the public key - ignored if {@code null}
     * @return the fingerprint or {@code null} if no key
     */
    public static String getFingerPrint(PublicKey key) {
        if (key == null) {
            return null;
        }

        try {
            Buffer buffer = new ByteArrayBuffer();
            buffer.putRawPublicKey(key);
            return getFingerPrint(buffer.array(), 0, buffer.wpos());
        } catch(Exception e) {
            return e.getClass().getSimpleName();
        }
    }

    public static String getFingerPrint(String password) {
        if (GenericUtils.isEmpty(password)) {
            return null;
        }
        
        try {
            return getFingerPrint(password.getBytes(StandardCharsets.UTF_8));
        } catch(Exception e) {
            return e.getClass().getSimpleName();
        }
    }
    
    public static String getFingerPrint(byte ... buf) throws Exception {
        return getFingerPrint(buf, 0, GenericUtils.length(buf));
    }
    
    public static String getFingerPrint(byte[] buf, int offset, int len) throws Exception {
        if (len <= 0) {
            return null;
        }

        Digest md5 = BuiltinDigests.md5.create();
        md5.init();
        md5.update(buf, offset, len);

        byte[] data = md5.digest();
        return BufferUtils.printHex(data, 0, data.length, ':');
    }

    /**
     * Retrieve the key type
     *
     * @param kp a key pair
     * @return the key type
     */
    public static String getKeyType(KeyPair kp) {
        return getKeyType(kp.getPrivate() != null ? kp.getPrivate() : kp.getPublic());
    }

    /**
     * Retrieve the key type
     *
     * @param key a public or private key
     * @return the key type
     */
    public static String getKeyType(Key key) {
        if (key instanceof DSAKey) {
            return KeyPairProvider.SSH_DSS;
        } else if (key instanceof RSAKey) {
            return KeyPairProvider.SSH_RSA;
        } else if (key instanceof ECKey) {
            ECKey ecKey = (ECKey) key;
            ECParameterSpec ecSpec = ecKey.getParams();
            return ECCurves.ECDSA_SHA2_PREFIX + ECCurves.getCurveName(ecSpec);
        }
        return null;
    }

    /**
     * @param key The {@link PublicKey} to be checked - ignored if {@code null}
     * @param keySet The keys to be searched - ignored if {@code null}/empty
     * @return The matching {@link PublicKey} from the keys or {@code null} if
     * no match found
     * @see #compareKeys(PublicKey, PublicKey)
     */
    public static PublicKey findMatchingKey(PublicKey key, PublicKey ... keySet) {
        if ((key == null) || GenericUtils.isEmpty(keySet)) {
            return null;
        } else {
            return findMatchingKey(key, Arrays.asList(keySet));
        }
    }

    /**
     * @param key The {@link PublicKey} to be checked - ignored if {@code null}
     * @param keySet The keys to be searched - ignored if {@code null}/empty
     * @return The matching {@link PublicKey} from the keys or {@code null} if
     * no match found
     * @see #compareKeys(PublicKey, PublicKey)
     */
    public static PublicKey findMatchingKey(PublicKey key, Collection<? extends PublicKey> keySet) {
        if ((key == null) || GenericUtils.isEmpty(keySet)) {
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
            return false;   // both null is covered by Objects#equals
        }
        
        if (compareKeys(k1.getPublic(), k2.getPublic())
         && compareKeys(k1.getPrivate(), k2.getPrivate())) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean compareKeys(PrivateKey k1, PrivateKey k2) {
        if ((k1 instanceof RSAPrivateKey) && (k2 instanceof RSAPrivateKey)) {
            return compareRSAKeys(RSAPrivateKey.class.cast(k1), RSAPrivateKey.class.cast(k2));
        } else if ((k1 instanceof DSAPrivateKey) && (k2 instanceof DSAPrivateKey)) {
            return compareDSAKeys(DSAPrivateKey.class.cast(k1), DSAPrivateKey.class.cast(k2));
        } else if ((k1 instanceof ECPrivateKey) && (k2 instanceof ECPrivateKey)) {
            return compareECKeys(ECPrivateKey.class.cast(k1), ECPrivateKey.class.cast(k2));
        } else {
            return false;   // either key is null or not of same class
        }
    }

    public static boolean compareRSAKeys(RSAPrivateKey k1, RSAPrivateKey k2) {
        if (Objects.equals(k1, k2)) {
            return true;
        } else if ((k1 == null) || (k2 == null)) {
            return false;   // both null is covered by Objects#equals
        } else if (Objects.equals(k1.getModulus(), k2.getModulus())
                && Objects.equals(k1.getPrivateExponent(), k2.getPrivateExponent())) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean compareDSAKeys(DSAPrivateKey k1, DSAPrivateKey k2) {
        if (Objects.equals(k1, k2)) {
            return true;
        } else if ((k1 == null) || (k2 == null)) {
            return false;   // both null is covered by Objects#equals
        } else if (Objects.equals(k1.getX(), k2.getAlgorithm())
                && compareDSAParams(k1.getParams(), k2.getParams())) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean compareECKeys(ECPrivateKey k1, ECPrivateKey k2) {
        if (Objects.equals(k1, k2)) {
            return true;
        } else if ((k1 == null) || (k2 == null)) {
            return false;   // both null is covered by Objects#equals
        } else if (Objects.equals(k1.getS(), k2.getS())
                && compareECParams(k1.getParams(), k2.getParams())) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean compareKeys(PublicKey k1, PublicKey k2) {
        if ((k1 instanceof RSAPublicKey) && (k2 instanceof RSAPublicKey)) {
            return compareRSAKeys(RSAPublicKey.class.cast(k1), RSAPublicKey.class.cast(k2));
        } else if ((k1 instanceof DSAPublicKey) && (k2 instanceof DSAPublicKey)) {
            return compareDSAKeys(DSAPublicKey.class.cast(k1), DSAPublicKey.class.cast(k2));
        } else if ((k1 instanceof ECPublicKey) && (k2 instanceof ECPublicKey)) {
            return compareECKeys(ECPublicKey.class.cast(k1), ECPublicKey.class.cast(k2));
        } else {
            return false;   // either key is null or not of same class
        }
    }
    
    public static boolean compareRSAKeys(RSAPublicKey k1, RSAPublicKey k2) {
        if (Objects.equals(k1, k2)) {
            return true;
        } else if ((k1 == null) || (k2 == null)) {
            return false;   // both null is covered by Objects#equals
        } else if (Objects.equals(k1.getPublicExponent(), k2.getPublicExponent())
                && Objects.equals(k1.getModulus(), k2.getModulus())) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean compareDSAKeys(DSAPublicKey k1, DSAPublicKey k2) {
        if (Objects.equals(k1, k2)) {
            return true;
        } else if ((k1 == null) || (k2 == null)) {
            return false;   // both null is covered by Objects#equals
        } else if (Objects.equals(k1.getY(), k2.getY())
                && compareDSAParams(k1.getParams(), k2.getParams())) {
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean compareDSAParams(DSAParams p1, DSAParams p2) {
        if (Objects.equals(p1, p2)) {
            return true;
        } else if ((p1 == null) || (p2 == null)) {
            return false;   // both null is covered by Objects#equals
        } else if (Objects.equals(p1.getG(), p2.getG())
                && Objects.equals(p1.getP(), p2.getP())
                && Objects.equals(p1.getQ(), p2.getQ())) {
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean compareECKeys(ECPublicKey k1, ECPublicKey k2) {
        if (Objects.equals(k1, k2)) {
            return true;
        } else if ((k1 == null) || (k2 == null)) {
            return false;   // both null is covered by Objects#equals
        } else if (Objects.equals(k1.getW(), k2.getW())
                && compareECParams(k1.getParams(), k2.getParams())) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean compareECParams(ECParameterSpec s1, ECParameterSpec s2) {
        if (Objects.equals(s1, s2)) {
            return true;
        } else if ((s1 == null) || (s2 == null)) {
            return false;   // both null is covered by Objects#equals
        } else if (Objects.equals(s1.getOrder(), s2.getOrder())
                && (s1.getCofactor() == s2.getCofactor())
                && Objects.equals(s1.getGenerator(), s2.getGenerator())
                && Objects.equals(s1.getCurve(), s2.getCurve())) {
            return true;
        } else {
            return false;
        }
    }
}
