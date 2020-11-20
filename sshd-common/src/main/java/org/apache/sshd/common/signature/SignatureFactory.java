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

package org.apache.sshd.common.signature;

import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.apache.sshd.common.BuiltinFactory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SignatureFactory extends BuiltinFactory<Signature> {
    /**
     * ECC signature types in ascending order of preference (i.e., most preferred 1st)
     */
    List<String> ECC_SIGNATURE_TYPE_PREFERENCES = Collections.unmodifiableList(
            Arrays.asList(
                    KeyPairProvider.ECDSA_SHA2_NISTP521,
                    KeyPairProvider.ECDSA_SHA2_NISTP384,
                    KeyPairProvider.ECDSA_SHA2_NISTP256));

    /**
     * RSA signature types in ascending order of preference (i.e., most preferred 1st)
     */
    List<String> RSA_SIGNATURE_TYPE_PREFERENCES = Collections.unmodifiableList(
            Arrays.asList(
                    KeyUtils.RSA_SHA512_KEY_TYPE_ALIAS,
                    KeyUtils.RSA_SHA256_KEY_TYPE_ALIAS,
                    KeyPairProvider.SSH_RSA));

    /**
     * @param  provided  The provided signature key types
     * @param  factories The available signature factories
     * @return           A {@link List} of the matching available factories names that are also listed as provided ones
     *                   - in the same <U>order</U> of preference as they appear in the available listing. May be empty
     *                   if no provided signature key types, or no available ones or no match found.
     * @see              #resolveSignatureFactoryNamesProposal(Iterable, Collection)
     */
    static List<String> resolveSignatureFactoriesProposal(
            Iterable<String> provided, Collection<? extends NamedFactory<Signature>> factories) {
        return resolveSignatureFactoryNamesProposal(provided, NamedResource.getNameList(factories));
    }

    /**
     * @param  provided  The provided signature key types
     * @param  available The available signature factories names
     * @return           A {@link List} of the matching available factories names that are also listed as provided ones
     *                   - in the same <U>order</U> of preference as they appear in the available listing. May be empty
     *                   if no provided signature key types, or no available ones or no match found.
     */
    static List<String> resolveSignatureFactoryNamesProposal(
            Iterable<String> provided, Collection<String> available) {
        if ((provided == null) || GenericUtils.isEmpty(available)) {
            return Collections.emptyList();
        }

        Set<String> providedKeys = new HashSet<>();
        for (String providedType : provided) {
            Collection<String> equivTypes = KeyUtils.getAllEquivalentKeyTypes(providedType);
            providedKeys.addAll(equivTypes);
        }

        if (GenericUtils.isEmpty(providedKeys)) {
            return Collections.emptyList();
        }

        // We want to preserve the original available order as it indicates the preference
        List<String> supported = new ArrayList<>(available);
        for (int index = 0; index < supported.size(); index++) {
            String kt = supported.get(index);
            if (!providedKeys.contains(kt)) {
                supported.remove(index);
                index--; // compensate for auto-increment
            }
        }

        return supported;
    }

    // returns -1 or > size() if append to end
    static int resolvePreferredSignaturePosition(
            List<? extends NamedFactory<Signature>> factories, NamedFactory<Signature> factory) {
        if (GenericUtils.isEmpty(factories)) {
            return -1; // just add it to the end
        }

        String name = factory.getName();
        if (KeyPairProvider.SSH_RSA.equalsIgnoreCase(name)) {
            return -1;
        }

        int pos = RSA_SIGNATURE_TYPE_PREFERENCES.indexOf(name);
        if (pos >= 0) {
            Map<String, Integer> posMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            for (int index = 0, count = factories.size(); index < count; index++) {
                NamedFactory<Signature> f = factories.get(index);
                String keyType = f.getName();
                String canonicalName = KeyUtils.getCanonicalKeyType(keyType);
                if (!KeyPairProvider.SSH_RSA.equalsIgnoreCase(canonicalName)) {
                    continue; // debug breakpoint
                }

                posMap.put(keyType, index);
            }

            return resolvePreferredSignaturePosition(RSA_SIGNATURE_TYPE_PREFERENCES, pos, posMap);
        }

        pos = ECC_SIGNATURE_TYPE_PREFERENCES.indexOf(name);
        if (pos >= 0) {
            Map<String, Integer> posMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            for (int index = 0, count = factories.size(); index < count; index++) {
                NamedFactory<Signature> f = factories.get(index);
                String keyType = f.getName();
                if (!ECC_SIGNATURE_TYPE_PREFERENCES.contains(keyType)) {
                    continue; // debug breakpoint
                }

                posMap.put(keyType, index);
            }

            return resolvePreferredSignaturePosition(ECC_SIGNATURE_TYPE_PREFERENCES, pos, posMap);
        }

        return -1; // no special preference - stick it as last
    }

    static int resolvePreferredSignaturePosition(
            List<String> preferredOrder, int prefValue, Map<String, Integer> posMap) {
        if (GenericUtils.isEmpty(preferredOrder) || (prefValue < 0) || GenericUtils.isEmpty(posMap)) {
            return -1;
        }

        int posValue = -1;
        for (Map.Entry<String, Integer> pe : posMap.entrySet()) {
            String name = pe.getKey();
            int order = preferredOrder.indexOf(name);
            if (order < 0) {
                continue; // should not happen, but tolerate
            }

            Integer curIndex = pe.getValue();
            int resIndex;
            if (order < prefValue) {
                resIndex = curIndex.intValue() + 1;
            } else if (order > prefValue) {
                resIndex = curIndex.intValue(); // by using same index we insert in front of it in effect
            } else {
                continue; // should not happen, but tolerate
            }

            // Preferred factories should be as close as possible to the beginning of the list
            if ((posValue < 0) || (resIndex < posValue)) {
                posValue = resIndex;
            }
        }

        return posValue;
    }

    static NamedFactory<? extends Signature> resolveSignatureFactory(
            String keyType, Collection<? extends NamedFactory<? extends Signature>> factories) {
        if (GenericUtils.isEmpty(keyType) || GenericUtils.isEmpty(factories)) {
            return null;
        }

        Collection<String> aliases = KeyUtils.getAllEquivalentKeyTypes(keyType);
        if (GenericUtils.isEmpty(aliases)) {
            return NamedResource.findByName(keyType, String.CASE_INSENSITIVE_ORDER, factories);
        } else {
            return NamedResource.findFirstMatchByName(aliases, String.CASE_INSENSITIVE_ORDER, factories);
        }
    }

    /**
     * @param  pubKey                  The intended {@link PublicKey} - ignored if {@code null}
     * @param  algo                    The intended signature algorithm - if {@code null}/empty and multiple signatures
     *                                 available for the key type then a default will be used. Otherwise, it is
     *                                 validated to make sure it matches the public key type
     * @return                         The {@link Signature} factory or {@code null} if no match found
     * @throws InvalidKeySpecException If specified algorithm does not match the selected public key
     */
    static NamedFactory<Signature> resolveSignatureFactoryByPublicKey(PublicKey pubKey, String algo)
            throws InvalidKeySpecException {
        if (pubKey == null) {
            return null;
        }

        NamedFactory<Signature> factory = null;
        if (pubKey instanceof DSAPublicKey) {
            factory = BuiltinSignatures.dsa;
        } else if (pubKey instanceof ECPublicKey) {
            ECPublicKey ecKey = (ECPublicKey) pubKey;
            factory = BuiltinSignatures.getFactoryByCurveSize(ecKey.getParams());
        } else if (pubKey instanceof RSAPublicKey) {
            // SSHD-1104 take into account key aliases
            if (GenericUtils.isEmpty(algo)) {
                factory = BuiltinSignatures.rsa;
            } else if (algo.contains("rsa")) {
                factory = BuiltinSignatures.fromFactoryName(algo);
            }
        } else if (SecurityUtils.EDDSA.equalsIgnoreCase(pubKey.getAlgorithm())) {
            factory = BuiltinSignatures.ed25519;
        }

        if (GenericUtils.isEmpty(algo) || (factory == null)) {
            return factory;
        }

        String name = factory.getName();
        if (!algo.equalsIgnoreCase(name)) {
            throw new InvalidKeySpecException(
                    "Mismatched factory name (" + name + ")"
                                              + " for algorithm=" + algo + " when using key type"
                                              + KeyUtils.getKeyType(pubKey));
        }

        return factory;
    }
}
