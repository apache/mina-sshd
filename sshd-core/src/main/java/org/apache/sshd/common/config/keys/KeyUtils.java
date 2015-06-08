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

import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
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
public class KeyUtils {
    private static final Map<String,PublicKeyEntryDecoder<? extends PublicKey>> byKeyTypeDecodersMap =
            new TreeMap<String, PublicKeyEntryDecoder<? extends PublicKey>>(String.CASE_INSENSITIVE_ORDER);
    private static final Map<Class<?>,PublicKeyEntryDecoder<? extends PublicKey>> byKeyClassDecodersMap =
            new HashMap<Class<?>, PublicKeyEntryDecoder<? extends PublicKey>>();

    static {
        registerPublicKeyEntryDecoder(RSAPublicKeyDecoder.INSTANCE);
        registerPublicKeyEntryDecoder(DSSPublicKeyEntryDecoder.INSTANCE);
        registerPublicKeyEntryDecoder(ECDSAPublicKeyEntryDecoder.INSTANCE);
    }

    private KeyUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    public static void registerPublicKeyEntryDecoder(PublicKeyEntryDecoder<? extends PublicKey> decoder) {
        ValidateUtils.checkNotNull(decoder, "No decoder specified", GenericUtils.EMPTY_OBJECT_ARRAY);

        Class<?> keyType = ValidateUtils.checkNotNull(decoder.getKeyType(), "No key type declared", GenericUtils.EMPTY_OBJECT_ARRAY);
        synchronized(byKeyClassDecodersMap) {
            byKeyClassDecodersMap.put(keyType, decoder);
        }

        Collection<String> names = ValidateUtils.checkNotNullAndNotEmpty(decoder.getSupportedTypeNames(), "No supported key type", GenericUtils.EMPTY_OBJECT_ARRAY);
        synchronized(byKeyTypeDecodersMap) {
            for (String n : names) {
                PublicKeyEntryDecoder<? extends PublicKey>  prev = byKeyTypeDecodersMap.put(n, decoder);
                if (prev != null) {
                    continue;   // debug breakpoint
                }
            }
        }
    }

    /**
     * @param keyType The {@code OpenSSH} key type string - ignored if {@code null}/empty
     * @return The registered {@link PublicKeyEntryDecoder} or {code null} if not found
     */
    public static PublicKeyEntryDecoder<? extends PublicKey> getPublicKeyEntryDecoder(String keyType) {
        if (GenericUtils.isEmpty(keyType)) {
            return null;
        }
        
        synchronized(byKeyTypeDecodersMap) {
            return byKeyTypeDecodersMap.get(keyType);
        }
    }
    
    /**
     * @param key The {@link PublicKey} - ignored if {@code null}
     * @return The registered {@link PublicKeyEntryDecoder} for this key or {code null} if no match found
     * @see #getPublicKeyEntryDecoder(Class)
     */
    public static PublicKeyEntryDecoder<? extends PublicKey> getPublicKeyEntryDecoder(PublicKey key) {
        if (key == null) {
            return null;
        } else {
            return getPublicKeyEntryDecoder(key.getClass());
        }
    }

    /**
     * @param keyType The key {@link Class} - ignored if {@code null} or not a {@link PublicKey}
     * compatible type
     * @return The registered {@link PublicKeyEntryDecoder} or {code null} if no match found
     */
    public static PublicKeyEntryDecoder<? extends PublicKey> getPublicKeyEntryDecoder(Class<?> keyType) {
        if ((keyType == null) || (!PublicKey.class.isAssignableFrom(keyType))) {
            return null;
        }
        
        synchronized(byKeyTypeDecodersMap) {
            {
                PublicKeyEntryDecoder<? extends PublicKey>  decoder=byKeyTypeDecodersMap.get(keyType);
                if (decoder != null) {
                    return decoder;
                }
            }
            
            // in case it is a derived class
            for (PublicKeyEntryDecoder<? extends PublicKey> decoder : byKeyTypeDecodersMap.values()) {
                Class<?> t = decoder.getKeyType();
                if (t.isAssignableFrom(keyType)) {
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
            Digest md5 = BuiltinDigests.md5.create();
            md5.init();
            md5.update(buffer.array(), 0, buffer.wpos());
            byte[] data = md5.digest();
            return BufferUtils.printHex(data, 0, data.length, ':');
        } catch(Exception e) {
            return "Unable to compute fingerprint";
        }
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
