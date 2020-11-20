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

import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.NamedFactoriesListParseResult;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.impl.SkECDSAPublicKeyEntryDecoder;
import org.apache.sshd.common.config.keys.impl.SkED25519PublicKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Provides easy access to the currently implemented signatures
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinSignatures implements SignatureFactory {
    /**
     * @deprecated
     * @see        <A HREF="https://issues.apache.org/jira/browse/SSHD-1004">SSHD-1004</A>
     */
    @Deprecated
    dsa(KeyPairProvider.SSH_DSS) {
        @Override
        public Signature create() {
            return new SignatureDSA();
        }
    },
    /**
     * @deprecated
     * @see        <A HREF="https://issues.apache.org/jira/browse/SSHD-1004">SSHD-1004</A>
     */
    @Deprecated
    dsa_cert(KeyPairProvider.SSH_DSS_CERT) {
        @Override
        public Signature create() {
            return new SignatureDSA();
        }
    },
    rsa(KeyPairProvider.SSH_RSA) {
        @Override
        public Signature create() {
            return new SignatureRSASHA1();
        }
    },
    /**
     * @deprecated
     * @see        <A HREF="https://issues.apache.org/jira/browse/SSHD-1004">SSHD-1004</A>
     */
    @Deprecated
    rsa_cert(KeyPairProvider.SSH_RSA_CERT) {
        @Override
        public Signature create() {
            return new SignatureRSASHA1();
        }
    },
    rsaSHA256(KeyUtils.RSA_SHA256_KEY_TYPE_ALIAS) {
        @Override
        public Signature create() {
            return new SignatureRSASHA256();
        }
    },
    rsaSHA256_cert(KeyUtils.RSA_SHA256_CERT_TYPE_ALIAS) {
        @Override
        public Signature create() {
            return new SignatureRSASHA256();
        }
    },
    rsaSHA512(KeyUtils.RSA_SHA512_KEY_TYPE_ALIAS) {
        private final AtomicReference<Boolean> supportHolder = new AtomicReference<>();

        @Override
        public Signature create() {
            return new SignatureRSASHA512();
        }

        @Override
        public boolean isSupported() {
            Boolean supported = supportHolder.get();
            if (supported == null) {
                try {
                    java.security.Signature sig = SecurityUtils.getSignature(SignatureRSASHA512.ALGORITHM);
                    supported = sig != null;
                } catch (Exception e) {
                    supported = Boolean.FALSE;
                }

                supportHolder.set(supported);
            }

            return supported;
        }
    },
    rsaSHA512_cert(KeyUtils.RSA_SHA512_CERT_TYPE_ALIAS) {
        private final AtomicReference<Boolean> supportHolder = new AtomicReference<>();

        @Override
        public Signature create() {
            return new SignatureRSASHA512();
        }

        @Override
        public boolean isSupported() {
            Boolean supported = supportHolder.get();
            if (supported == null) {
                try {
                    java.security.Signature sig = SecurityUtils.getSignature(SignatureRSASHA512.ALGORITHM);
                    supported = sig != null;
                } catch (Exception e) {
                    supported = Boolean.FALSE;
                }

                supportHolder.set(supported);
            }

            return supported;
        }
    },
    nistp256(KeyPairProvider.ECDSA_SHA2_NISTP256) {
        @Override
        public Signature create() {
            return new SignatureECDSA.SignatureECDSA256();
        }

        @Override
        public boolean isSupported() {
            return SecurityUtils.isECCSupported();
        }
    },
    nistp256_cert(KeyPairProvider.SSH_ECDSA_SHA2_NISTP256_CERT) {
        @Override
        public Signature create() {
            return new SignatureECDSA.SignatureECDSA256();
        }

        @Override
        public boolean isSupported() {
            return SecurityUtils.isECCSupported();
        }
    },
    nistp384(KeyPairProvider.ECDSA_SHA2_NISTP384) {
        @Override
        public Signature create() {
            return new SignatureECDSA.SignatureECDSA384();
        }

        @Override
        public boolean isSupported() {
            return SecurityUtils.isECCSupported();
        }
    },
    nistp384_cert(KeyPairProvider.SSH_ECDSA_SHA2_NISTP384_CERT) {
        @Override
        public Signature create() {
            return new SignatureECDSA.SignatureECDSA384();
        }

        @Override
        public boolean isSupported() {
            return SecurityUtils.isECCSupported();
        }
    },
    nistp521(KeyPairProvider.ECDSA_SHA2_NISTP521) {
        @Override
        public Signature create() {
            return new SignatureECDSA.SignatureECDSA521();
        }

        @Override
        public boolean isSupported() {
            return SecurityUtils.isECCSupported();
        }
    },
    nistp521_cert(KeyPairProvider.SSH_ECDSA_SHA2_NISTP521_CERT) {
        @Override
        public Signature create() {
            return new SignatureECDSA.SignatureECDSA521();
        }

        @Override
        public boolean isSupported() {
            return SecurityUtils.isECCSupported();
        }
    },
    sk_ecdsa_sha2_nistp256(SkECDSAPublicKeyEntryDecoder.KEY_TYPE) {
        @Override
        public Signature create() {
            return new SignatureSkECDSA();
        }

        @Override
        public boolean isSupported() {
            return SecurityUtils.isECCSupported();
        }
    },
    ed25519(KeyPairProvider.SSH_ED25519) {
        @Override
        public Signature create() {
            return SecurityUtils.getEDDSASigner();
        }

        @Override
        public boolean isSupported() {
            return SecurityUtils.isEDDSACurveSupported();
        }
    },
    ed25519_cert(KeyPairProvider.SSH_ED25519_CERT) {
        @Override
        public Signature create() {
            return SecurityUtils.getEDDSASigner();
        }

        @Override
        public boolean isSupported() {
            return SecurityUtils.isEDDSACurveSupported();
        }
    },
    sk_ssh_ed25519(SkED25519PublicKeyEntryDecoder.KEY_TYPE) {
        @Override
        public Signature create() {
            return new SignatureSkED25519();
        }

        @Override
        public boolean isSupported() {
            return SecurityUtils.isEDDSACurveSupported();
        }
    };

    public static final Set<BuiltinSignatures> VALUES = Collections.unmodifiableSet(EnumSet.allOf(BuiltinSignatures.class));

    private static final Map<String, SignatureFactory> EXTENSIONS = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    private final String factoryName;

    BuiltinSignatures(String facName) {
        factoryName = facName;
    }

    public static BuiltinSignatures getFactoryByCurveSize(ECParameterSpec params) {
        int curveSize = ECCurves.getCurveSize(params);
        if (curveSize <= 256) {
            return nistp256;
        } else if (curveSize <= 384) {
            return nistp384;
        } else {
            return nistp521;
        }
    }

    public static Signature getSignerByCurveSize(ECParameterSpec params) {
        NamedFactory<Signature> factory = getFactoryByCurveSize(params);
        return (factory == null) ? null : factory.create();
    }

    @Override
    public final String getName() {
        return factoryName;
    }

    @Override
    public final String toString() {
        return getName();
    }

    @Override
    public boolean isSupported() {
        return true;
    }

    /**
     * Registered a {@link NamedFactory} to be available besides the built-in ones when parsing configuration
     *
     * @param  extension                The factory to register
     * @throws IllegalArgumentException if factory instance is {@code null}, or overrides a built-in one or overrides
     *                                  another registered factory with the same name (case <U>insensitive</U>).
     */
    public static void registerExtension(SignatureFactory extension) {
        String name = Objects.requireNonNull(extension, "No extension provided").getName();
        ValidateUtils.checkTrue(fromFactoryName(name) == null, "Extension overrides built-in: %s", name);

        synchronized (EXTENSIONS) {
            ValidateUtils.checkTrue(!EXTENSIONS.containsKey(name), "Extension overrides existing: %s", name);
            EXTENSIONS.put(name, extension);
        }
    }

    /**
     * @return A {@link NavigableSet} of the currently registered extensions, sorted according to the factory name (case
     *         <U>insensitive</U>)
     */
    public static NavigableSet<SignatureFactory> getRegisteredExtensions() {
        synchronized (EXTENSIONS) {
            return GenericUtils.asSortedSet(NamedResource.BY_NAME_COMPARATOR, EXTENSIONS.values());
        }
    }

    /**
     * Unregisters specified extension
     *
     * @param  name The factory name - ignored if {@code null}/empty
     * @return      The registered extension - {@code null} if not found
     */
    public static SignatureFactory unregisterExtension(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        synchronized (EXTENSIONS) {
            return EXTENSIONS.remove(name);
        }
    }

    /**
     * @param  s The {@link Enum}'s name - ignored if {@code null}/empty
     * @return   The matching {@link org.apache.sshd.common.signature.BuiltinSignatures} whose {@link Enum#name()}
     *           matches (case <U>insensitive</U>) the provided argument - {@code null} if no match
     */
    public static BuiltinSignatures fromString(String s) {
        if (GenericUtils.isEmpty(s)) {
            return null;
        }

        for (BuiltinSignatures c : VALUES) {
            if (s.equalsIgnoreCase(c.name())) {
                return c;
            }
        }

        return null;
    }

    /**
     * @param  factory The {@link org.apache.sshd.common.NamedFactory} for the signature - ignored if {@code null}
     * @return         The matching {@link org.apache.sshd.common.signature.BuiltinSignatures} whose factory name
     *                 matches (case <U>insensitive</U>) the digest factory name
     * @see            #fromFactoryName(String)
     */
    public static BuiltinSignatures fromFactory(NamedFactory<Signature> factory) {
        if (factory == null) {
            return null;
        } else {
            return fromFactoryName(factory.getName());
        }
    }

    /**
     * @param  name The factory name - ignored if {@code null}/empty
     * @return      The matching {@link BuiltinSignatures} whose factory name matches (case <U>insensitive</U>) the
     *              provided name - {@code null} if no match
     */
    public static BuiltinSignatures fromFactoryName(String name) {
        return NamedResource.findByName(name, String.CASE_INSENSITIVE_ORDER, VALUES);
    }

    /**
     * @param  sigs A comma-separated list of signatures' names - ignored if {@code null}/empty
     * @return      A {@link ParseResult} of all the {@link NamedFactory} whose name appears in the string and represent
     *              a built-in signature. Any unknown name is <U>ignored</U>. The order of the returned result is the
     *              same as the original order - bar the unknown signatures. <B>Note:</B> it is up to caller to ensure
     *              that the list does not contain duplicates
     */
    public static ParseResult parseSignatureList(String sigs) {
        return parseSignatureList(GenericUtils.split(sigs, ','));
    }

    public static ParseResult parseSignatureList(String... sigs) {
        return parseSignatureList(GenericUtils.isEmpty((Object[]) sigs) ? Collections.emptyList() : Arrays.asList(sigs));
    }

    public static ParseResult parseSignatureList(Collection<String> sigs) {
        if (GenericUtils.isEmpty(sigs)) {
            return ParseResult.EMPTY;
        }

        List<SignatureFactory> factories = new ArrayList<>(sigs.size());
        List<String> unknown = Collections.emptyList();
        for (String name : sigs) {
            SignatureFactory s = resolveFactory(name);
            if (s != null) {
                factories.add(s);
            } else {
                // replace the (unmodifiable) empty list with a real one
                if (unknown.isEmpty()) {
                    unknown = new ArrayList<>();
                }
                unknown.add(name);
            }
        }

        return new ParseResult(factories, unknown);
    }

    /**
     * @param  name The factory name
     * @return      The factory or {@code null} if it is neither a built-in one or a registered extension
     */
    public static SignatureFactory resolveFactory(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        SignatureFactory s = fromFactoryName(name);
        if (s != null) {
            return s;
        }

        synchronized (EXTENSIONS) {
            return EXTENSIONS.get(name);
        }
    }

    /**
     * Holds the result of the {@link BuiltinSignatures#parseSignatureList(String)}
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    public static final class ParseResult extends NamedFactoriesListParseResult<Signature, SignatureFactory> {
        public static final ParseResult EMPTY = new ParseResult(Collections.emptyList(), Collections.emptyList());

        public ParseResult(List<SignatureFactory> parsed, List<String> unsupported) {
            super(parsed, unsupported);
        }
    }
}
