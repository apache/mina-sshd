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

package org.apache.sshd.common.kex;

import java.math.BigInteger;
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

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.NamedResourceListParseResult;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinDHFactories implements DHFactory {
    /**
     * @deprecated
     * @see        <A HREF="https://issues.apache.org/jira/browse/SSHD-1004">SSHD-1004</A>
     */
    @Deprecated
    dhg1(Constants.DIFFIE_HELLMAN_GROUP1_SHA1) {
        @Override
        public DHG create(Object... params) throws Exception {
            if (!GenericUtils.isEmpty(params)) {
                throw new IllegalArgumentException("No accepted parameters for " + getName());
            }
            return new DHG(BuiltinDigests.sha1, new BigInteger(DHGroupData.getP1()), new BigInteger(DHGroupData.getG()));
        }

        @Override // see https://tools.ietf.org/html/rfc4253#page-23
        public boolean isSupported() {
            return SecurityUtils.isDHOakelyGroupSupported(1024) && BuiltinDigests.sha1.isSupported();
        }
    },
    /**
     * @deprecated
     * @see        <A HREF="https://issues.apache.org/jira/browse/SSHD-1004">SSHD-1004</A>
     */
    @Deprecated
    dhg14(Constants.DIFFIE_HELLMAN_GROUP14_SHA1) {
        @Override
        public DHG create(Object... params) throws Exception {
            if (!GenericUtils.isEmpty(params)) {
                throw new IllegalArgumentException("No accepted parameters for " + getName());
            }
            return new DHG(BuiltinDigests.sha1, new BigInteger(DHGroupData.getP14()), new BigInteger(DHGroupData.getG()));
        }

        @Override // see https://tools.ietf.org/html/rfc4253#page-23
        public boolean isSupported() {
            return SecurityUtils.isDHOakelyGroupSupported(2048) && BuiltinDigests.sha1.isSupported();
        }
    },
    dhg14_256(Constants.DIFFIE_HELLMAN_GROUP14_SHA256) {
        @Override
        public DHG create(Object... params) throws Exception {
            if (!GenericUtils.isEmpty(params)) {
                throw new IllegalArgumentException("No accepted parameters for " + getName());
            }
            return new DHG(BuiltinDigests.sha256, new BigInteger(DHGroupData.getP14()), new BigInteger(DHGroupData.getG()));
        }

        @Override // see https://tools.ietf.org/html/rfc4253#page-23
        public boolean isSupported() {
            return SecurityUtils.isDHOakelyGroupSupported(2048) && BuiltinDigests.sha256.isSupported();
        }
    },
    dhg15_512(Constants.DIFFIE_HELLMAN_GROUP15_SHA512) {
        @Override
        public DHG create(Object... params) throws Exception {
            if (!GenericUtils.isEmpty(params)) {
                throw new IllegalArgumentException("No accepted parameters for " + getName());
            }
            return new DHG(BuiltinDigests.sha512, new BigInteger(DHGroupData.getP15()), new BigInteger(DHGroupData.getG()));
        }

        @Override // see https://tools.ietf.org/html/rfc4253#page-23
        public boolean isSupported() {
            return SecurityUtils.isDHOakelyGroupSupported(3072) && BuiltinDigests.sha512.isSupported();
        }
    },
    dhg16_512(Constants.DIFFIE_HELLMAN_GROUP16_SHA512) {
        @Override
        public DHG create(Object... params) throws Exception {
            if (!GenericUtils.isEmpty(params)) {
                throw new IllegalArgumentException("No accepted parameters for " + getName());
            }
            return new DHG(BuiltinDigests.sha512, new BigInteger(DHGroupData.getP16()), new BigInteger(DHGroupData.getG()));
        }

        @Override // see https://tools.ietf.org/html/rfc4253#page-23
        public boolean isSupported() {
            return SecurityUtils.isDHOakelyGroupSupported(4096) && BuiltinDigests.sha512.isSupported();
        }
    },
    dhg17_512(Constants.DIFFIE_HELLMAN_GROUP17_SHA512) {
        @Override
        public DHG create(Object... params) throws Exception {
            if (!GenericUtils.isEmpty(params)) {
                throw new IllegalArgumentException("No accepted parameters for " + getName());
            }
            return new DHG(BuiltinDigests.sha512, new BigInteger(DHGroupData.getP17()), new BigInteger(DHGroupData.getG()));
        }

        @Override // see https://tools.ietf.org/html/rfc4253#page-23
        public boolean isSupported() {
            return SecurityUtils.isDHOakelyGroupSupported(6144) && BuiltinDigests.sha512.isSupported();
        }
    },
    dhg18_512(Constants.DIFFIE_HELLMAN_GROUP18_SHA512) {
        @Override
        public DHG create(Object... params) throws Exception {
            if (!GenericUtils.isEmpty(params)) {
                throw new IllegalArgumentException("No accepted parameters for " + getName());
            }
            return new DHG(BuiltinDigests.sha512, new BigInteger(DHGroupData.getP18()), new BigInteger(DHGroupData.getG()));
        }

        @Override // see https://tools.ietf.org/html/rfc4253#page-23
        public boolean isSupported() {
            return SecurityUtils.isDHOakelyGroupSupported(8192) && BuiltinDigests.sha512.isSupported();
        }
    },
    /**
     * @deprecated
     * @see        <A HREF="https://issues.apache.org/jira/browse/SSHD-1004">SSHD-1004</A>
     */
    @Deprecated
    dhgex(Constants.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1) {
        @Override
        public DHG create(Object... params) throws Exception {
            if ((GenericUtils.length(params) != 2)
                    || (!(params[0] instanceof BigInteger))
                    || (!(params[1] instanceof BigInteger))) {
                throw new IllegalArgumentException("Bad parameters for " + getName());
            }
            return new DHG(BuiltinDigests.sha1, (BigInteger) params[0], (BigInteger) params[1]);
        }

        @Override
        public boolean isGroupExchange() {
            return true;
        }

        @Override
        public boolean isSupported() { // avoid "Prime size must be multiple of 64, and can only range from 512 to 2048
                                      // (inclusive)"
            return SecurityUtils.isDHGroupExchangeSupported() && BuiltinDigests.sha1.isSupported();
        }
    },
    dhgex256(Constants.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256) {
        @Override
        public AbstractDH create(Object... params) throws Exception {
            if ((GenericUtils.length(params) != 2)
                    || (!(params[0] instanceof BigInteger))
                    || (!(params[1] instanceof BigInteger))) {
                throw new IllegalArgumentException("Bad parameters for " + getName());
            }
            return new DHG(BuiltinDigests.sha256, (BigInteger) params[0], (BigInteger) params[1]);
        }

        @Override
        public boolean isSupported() { // avoid "Prime size must be multiple of 64, and can only range from 512 to 2048
                                      // (inclusive)"
            return SecurityUtils.isDHGroupExchangeSupported() && BuiltinDigests.sha256.isSupported();
        }

        @Override
        public boolean isGroupExchange() {
            return true;
        }
    },
    ecdhp256(Constants.ECDH_SHA2_NISTP256) {
        @Override
        public ECDH create(Object... params) throws Exception {
            if (!GenericUtils.isEmpty(params)) {
                throw new IllegalArgumentException("No accepted parameters for " + getName());
            }
            return new ECDH(ECCurves.nistp256);
        }

        @Override
        public boolean isSupported() {
            return ECCurves.nistp256.isSupported();
        }
    },
    ecdhp384(Constants.ECDH_SHA2_NISTP384) {
        @Override
        public ECDH create(Object... params) throws Exception {
            if (!GenericUtils.isEmpty(params)) {
                throw new IllegalArgumentException("No accepted parameters for " + getName());
            }
            return new ECDH(ECCurves.nistp384);
        }

        @Override
        public boolean isSupported() {
            return ECCurves.nistp384.isSupported();
        }
    },
    ecdhp521(Constants.ECDH_SHA2_NISTP521) {
        @Override
        public ECDH create(Object... params) throws Exception {
            if (!GenericUtils.isEmpty(params)) {
                throw new IllegalArgumentException("No accepted parameters for " + getName());
            }
            return new ECDH(ECCurves.nistp521);
        }

        @Override
        public boolean isSupported() {
            return ECCurves.nistp521.isSupported();
        }
    },
    /**
     * @see <a href="https://www.rfc-editor.org/info/rfc8731">RFC 8731</a>
     */
    curve25519(Constants.CURVE25519_SHA256) {
        @Override
        public XDH create(Object... params) throws Exception {
            if (!GenericUtils.isEmpty(params)) {
                throw new IllegalArgumentException("No accepted parameters for " + getName());
            }
            return new XDH(MontgomeryCurve.x25519, false) {

                @Override
                public Digest getHash() throws Exception {
                    return BuiltinDigests.sha256.create();
                }

            };
        }

        @Override
        public boolean isSupported() {
            return MontgomeryCurve.x25519.isSupported() && BuiltinDigests.sha256.isSupported();
        }
    },
    curve25519_libssh(Constants.CURVE25519_SHA256_LIBSSH) {
        @Override
        public AbstractDH create(Object... params) throws Exception {
            return curve25519.create(params);
        }

        @Override
        public boolean isSupported() {
            return curve25519.isSupported();
        }
    },
    /**
     * @see <a href="https://www.rfc-editor.org/info/rfc8731">RFC 8731</a>
     */
    curve448(Constants.CURVE448_SHA512) {
        @Override
        public XDH create(Object... params) throws Exception {
            if (!GenericUtils.isEmpty(params)) {
                throw new IllegalArgumentException("No accepted parameters for " + getName());
            }
            return new XDH(MontgomeryCurve.x448, false) {

                @Override
                public Digest getHash() throws Exception {
                    return BuiltinDigests.sha512.create();
                }
            };
        }

        @Override
        public boolean isSupported() {
            return MontgomeryCurve.x448.isSupported() && BuiltinDigests.sha512.isSupported();
        }
    },
    /**
     * @see <a href= "https://datatracker.ietf.org/doc/html/draft-kampanakis-curdle-ssh-pq-ke-04">PQ/T Hybrid Key
     *      Exchange in SSH</a>
     */
    mlkem768x25519(Constants.MLKEM768_25519_SHA256) {
        @Override
        public XDH create(Object... params) throws Exception {
            if (!GenericUtils.isEmpty(params)) {
                throw new IllegalArgumentException("No accepted parameters for " + getName());
            }
            return new XDH(MontgomeryCurve.x25519, true) {

                @Override
                public KeyEncapsulationMethod getKeyEncapsulation() {
                    return BuiltinKEM.mlkem768;
                }

                @Override
                public Digest getHash() throws Exception {
                    return BuiltinDigests.sha256.create();
                }
            };
        }

        @Override
        public boolean isSupported() {
            return MontgomeryCurve.x25519.isSupported() && BuiltinDigests.sha256.isSupported()
                    && BuiltinKEM.mlkem768.isSupported();
        }
    },
    /**
     * @see <a href= "https://datatracker.ietf.org/doc/html/draft-kampanakis-curdle-ssh-pq-ke-04">PQ/T Hybrid Key
     *      Exchange in SSH</a>
     */
    mlkem768nistp256(Constants.MLKEM768_NISTP256_SHA256) {
        @Override
        public ECDH create(Object... params) throws Exception {
            if (!GenericUtils.isEmpty(params)) {
                throw new IllegalArgumentException("No accepted parameters for " + getName());
            }
            return new ECDH(ECCurves.nistp256, true) {

                @Override
                public KeyEncapsulationMethod getKeyEncapsulation() {
                    return BuiltinKEM.mlkem768;
                }

            };
        }

        @Override
        public boolean isSupported() {
            return ECCurves.nistp256.isSupported() && BuiltinKEM.mlkem768.isSupported();
        }
    },
    /**
     * @see <a href= "https://datatracker.ietf.org/doc/html/draft-kampanakis-curdle-ssh-pq-ke-04">PQ/T Hybrid Key
     *      Exchange in SSH</a>
     */
    mlkem1024nistp384(Constants.MLKEM1024_NISTP384_SHA384) {
        @Override
        public ECDH create(Object... params) throws Exception {
            if (!GenericUtils.isEmpty(params)) {
                throw new IllegalArgumentException("No accepted parameters for " + getName());
            }
            return new ECDH(ECCurves.nistp384, true) {

                @Override
                public KeyEncapsulationMethod getKeyEncapsulation() {
                    return BuiltinKEM.mlkem1024;
                }

            };
        }

        @Override
        public boolean isSupported() {
            return ECCurves.nistp384.isSupported() && BuiltinKEM.mlkem1024.isSupported();
        }
    },
    /**
     * @see <a href=
     *      "https://www.ietf.org/archive/id/draft-josefsson-ntruprime-ssh-02.html">draft-josefsson-ntruprime-ssh-02.html</a>
     */
    sntrup761x25519(Constants.SNTRUP761_25519_SHA512) {
        @Override
        public XDH create(Object... params) throws Exception {
            if (!GenericUtils.isEmpty(params)) {
                throw new IllegalArgumentException("No accepted parameters for " + getName());
            }
            return new XDH(MontgomeryCurve.x25519, true) {

                @Override
                public KeyEncapsulationMethod getKeyEncapsulation() {
                    return BuiltinKEM.sntrup761;
                }

                @Override
                public Digest getHash() throws Exception {
                    return BuiltinDigests.sha512.create();
                }
            };
        }

        @Override
        public boolean isSupported() {
            return MontgomeryCurve.x25519.isSupported() && BuiltinDigests.sha512.isSupported()
                    && BuiltinKEM.sntrup761.isSupported();
        }
    },
    /**
     * @see <a href=
     *      "https://www.ietf.org/archive/id/draft-josefsson-ntruprime-ssh-02.html">draft-josefsson-ntruprime-ssh-02.html</a>
     */
    sntrup761x25519_openssh(Constants.SNTRUP761_25519_SHA512_OPENSSH) {
        @Override
        public AbstractDH create(Object... params) throws Exception {
            return sntrup761x25519.create(params);
        }

        @Override
        public boolean isSupported() {
            return sntrup761x25519.isSupported();
        }
    };

    public static final Set<BuiltinDHFactories> VALUES = Collections.unmodifiableSet(EnumSet.allOf(BuiltinDHFactories.class));

    private static final Map<String, DHFactory> EXTENSIONS = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    private final String factoryName;

    BuiltinDHFactories(String name) {
        factoryName = name;
    }

    @Override
    public final String getName() {
        return factoryName;
    }

    @Override
    public boolean isSupported() {
        return true;
    }

    @Override
    public final String toString() {
        return getName();
    }

    /**
     * Registered a {@link org.apache.sshd.common.NamedFactory} to be available besides the built-in ones when parsing
     * configuration
     *
     * @param  extension                The factory to register
     * @throws IllegalArgumentException if factory instance is {@code null}, or overrides a built-in one or overrides
     *                                  another registered factory with the same name (case <U>insensitive</U>).
     */
    public static void registerExtension(DHFactory extension) {
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
    public static NavigableSet<DHFactory> getRegisteredExtensions() {
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
    public static DHFactory unregisterExtension(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        synchronized (EXTENSIONS) {
            return EXTENSIONS.remove(name);
        }
    }

    /**
     * @param  name The factory name - ignored if {@code null}/empty
     * @return      The matching {@link BuiltinDHFactories} (case <U>insensitive</U>) or {@code null} if no match found
     */
    public static BuiltinDHFactories fromFactoryName(String name) {
        return NamedResource.findByName(name, String.CASE_INSENSITIVE_ORDER, VALUES);
    }

    @Override
    public boolean isGroupExchange() {
        return false;
    }

    /**
     * @param  dhList A comma-separated list of ciphers' names - ignored if {@code null}/empty
     * @return        A {@link ParseResult} of all the {@link DHFactory}-ies whose name appears in the string and
     *                represent a built-in value. Any unknown name is <U>ignored</U>. The order of the returned result
     *                is the same as the original order - bar the unknown ones. <B>Note:</B> it is up to caller to
     *                ensure that the list does not contain duplicates
     */
    public static ParseResult parseDHFactoriesList(String dhList) {
        return parseDHFactoriesList(GenericUtils.split(dhList, ','));
    }

    public static ParseResult parseDHFactoriesList(String... dhList) {
        return parseDHFactoriesList(GenericUtils.isEmpty((Object[]) dhList) ? Collections.emptyList() : Arrays.asList(dhList));
    }

    public static ParseResult parseDHFactoriesList(Collection<String> dhList) {
        if (GenericUtils.isEmpty(dhList)) {
            return ParseResult.EMPTY;
        }

        List<DHFactory> factories = new ArrayList<>(dhList.size());
        List<String> unknown = Collections.emptyList();
        for (String name : dhList) {
            DHFactory f = resolveFactory(name);
            if (f != null) {
                factories.add(f);
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
    public static DHFactory resolveFactory(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        DHFactory s = fromFactoryName(name);
        if (s != null) {
            return s;
        }

        synchronized (EXTENSIONS) {
            return EXTENSIONS.get(name);
        }
    }

    /**
     * Represents the result of {@link BuiltinDHFactories#parseDHFactoriesList(String)}
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    public static final class ParseResult extends NamedResourceListParseResult<DHFactory> {
        public static final ParseResult EMPTY = new ParseResult(Collections.emptyList(), Collections.emptyList());

        public ParseResult(List<DHFactory> parsed, List<String> unsupported) {
            super(parsed, unsupported);
        }

        public List<DHFactory> getParsedFactories() {
            return getParsedResources();
        }

        public List<String> getUnsupportedFactories() {
            return getUnsupportedResources();
        }
    }

    public static final class Constants {
        public static final String DIFFIE_HELLMAN_GROUP1_SHA1 = "diffie-hellman-group1-sha1";
        public static final String DIFFIE_HELLMAN_GROUP14_SHA1 = "diffie-hellman-group14-sha1";
        public static final String DIFFIE_HELLMAN_GROUP14_SHA256 = "diffie-hellman-group14-sha256";
        public static final String DIFFIE_HELLMAN_GROUP15_SHA512 = "diffie-hellman-group15-sha512";
        public static final String DIFFIE_HELLMAN_GROUP16_SHA512 = "diffie-hellman-group16-sha512";
        public static final String DIFFIE_HELLMAN_GROUP17_SHA512 = "diffie-hellman-group17-sha512";
        public static final String DIFFIE_HELLMAN_GROUP18_SHA512 = "diffie-hellman-group18-sha512";
        public static final String DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1 = "diffie-hellman-group-exchange-sha1";
        public static final String DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256 = "diffie-hellman-group-exchange-sha256";
        public static final String ECDH_SHA2_NISTP256 = "ecdh-sha2-nistp256";
        public static final String ECDH_SHA2_NISTP384 = "ecdh-sha2-nistp384";
        public static final String ECDH_SHA2_NISTP521 = "ecdh-sha2-nistp521";
        public static final String CURVE25519_SHA256 = "curve25519-sha256";
        public static final String CURVE25519_SHA256_LIBSSH = CURVE25519_SHA256 + "@libssh.org";
        public static final String CURVE448_SHA512 = "curve448-sha512";
        public static final String MLKEM768_25519_SHA256 = "mlkem768x25519-sha256";
        public static final String MLKEM768_NISTP256_SHA256 = "mlkem768nistp256-sha256";
        public static final String MLKEM1024_NISTP384_SHA384 = "mlkem1024nistp384-sha384";
        public static final String SNTRUP761_25519_SHA512 = "sntrup761x25519-sha512";
        public static final String SNTRUP761_25519_SHA512_OPENSSH = SNTRUP761_25519_SHA512 + "@openssh.com";

        private Constants() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }
}
