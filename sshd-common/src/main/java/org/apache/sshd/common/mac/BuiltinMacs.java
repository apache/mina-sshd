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

package org.apache.sshd.common.mac;

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

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.NamedFactoriesListParseResult;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Provides easy access to the currently implemented macs
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinMacs implements MacFactory {
    /**
     * @deprecated
     * @see        <A HREF="https://issues.apache.org/jira/browse/SSHD-1004">SSHD-1004</A>
     */
    @Deprecated
    hmacmd5(Constants.HMAC_MD5, "HmacMD5", 16, 16),
    /**
     * @deprecated
     * @see        <A HREF="https://issues.apache.org/jira/browse/SSHD-1004">SSHD-1004</A>
     */
    @Deprecated
    hmacmd596(Constants.HMAC_MD5_96, "HmacMD5", 12, 16),
    hmacsha1(Constants.HMAC_SHA1, "HmacSHA1", 20, 20),
    hmacsha1etm(Constants.ETM_HMAC_SHA1, "HmacSHA1", 20, 20) {
        @Override
        public boolean isEncryptThenMac() {
            return true;
        }
    },
    /**
     * @deprecated
     * @see        <A HREF="https://issues.apache.org/jira/browse/SSHD-1004">SSHD-1004</A>
     */
    @Deprecated
    hmacsha196(Constants.HMAC_SHA1_96, "HmacSHA1", 12, 20),
    /** See <A HREF="https://tools.ietf.org/html/rfc6668">RFC 6668</A> */
    hmacsha256(Constants.HMAC_SHA2_256, "HmacSHA256", 32, 32),
    hmacsha256etm(Constants.ETM_HMAC_SHA2_256, "HmacSHA256", 32, 32) {
        @Override
        public boolean isEncryptThenMac() {
            return true;
        }
    },
    /** See <A HREF="https://tools.ietf.org/html/rfc6668">RFC 6668</A> */
    hmacsha512(Constants.HMAC_SHA2_512, "HmacSHA512", 64, 64),
    hmacsha512etm(Constants.ETM_HMAC_SHA2_512, "HmacSHA512", 64, 64) {
        @Override
        public boolean isEncryptThenMac() {
            return true;
        }
    };

    public static final Set<BuiltinMacs> VALUES = Collections.unmodifiableSet(EnumSet.allOf(BuiltinMacs.class));

    private static final Map<String, MacFactory> EXTENSIONS = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    private final String factoryName;
    private final String algorithm;
    private final int defbsize;
    private final int bsize;

    BuiltinMacs(String factoryName, String algorithm, int bsize, int defbsize) {
        this.factoryName = factoryName;
        this.algorithm = algorithm;
        this.bsize = bsize;
        this.defbsize = defbsize;
    }

    @Override
    public Mac create() {
        return new BaseMac(getAlgorithm(), getBlockSize(), getDefaultBlockSize(), isEncryptThenMac());
    }

    @Override
    public final String getName() {
        return factoryName;
    }

    @Override
    public final String getAlgorithm() {
        return algorithm;
    }

    @Override
    public final int getBlockSize() {
        return bsize;
    }

    @Override
    public final int getDefaultBlockSize() {
        return defbsize;
    }

    @Override
    public final boolean isSupported() {
        return true;
    }

    @Override
    public final String toString() {
        return getName();
    }

    /**
     * Registered a {@link NamedFactory} to be available besides the built-in ones when parsing configuration
     *
     * @param  extension                The factory to register
     * @throws IllegalArgumentException if factory instance is {@code null}, or overrides a built-in one or overrides
     *                                  another registered factory with the same name (case <U>insensitive</U>).
     */
    public static void registerExtension(MacFactory extension) {
        String name = Objects.requireNonNull(extension, "No extension provided").getName();
        ValidateUtils.checkTrue(
                fromFactoryName(name) == null, "Extension overrides built-in: %s", name);

        synchronized (EXTENSIONS) {
            ValidateUtils.checkTrue(
                    !EXTENSIONS.containsKey(name), "Extension overrides existing: %s", name);
            EXTENSIONS.put(name, extension);
        }
    }

    /**
     * @return A {@link NavigableSet} of the currently registered extensions, sorted according to the factory name (case
     *         <U>insensitive</U>)
     */
    public static NavigableSet<MacFactory> getRegisteredExtensions() {
        synchronized (EXTENSIONS) {
            return GenericUtils.asSortedSet(
                    NamedResource.BY_NAME_COMPARATOR, EXTENSIONS.values());
        }
    }

    /**
     * Unregisters specified extension
     *
     * @param  name The factory name - ignored if {@code null}/empty
     * @return      The registered extension - {@code null} if not found
     */
    public static MacFactory unregisterExtension(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        synchronized (EXTENSIONS) {
            return EXTENSIONS.remove(name);
        }
    }

    /**
     * @param  s The {@link Enum}'s name - ignored if {@code null}/empty
     * @return   The matching {@link org.apache.sshd.common.mac.BuiltinMacs} whose {@link Enum#name()} matches (case
     *           <U>insensitive</U>) the provided argument - {@code null} if no match
     */
    public static BuiltinMacs fromString(String s) {
        if (GenericUtils.isEmpty(s)) {
            return null;
        }

        for (BuiltinMacs c : VALUES) {
            if (s.equalsIgnoreCase(c.name())) {
                return c;
            }
        }

        return null;
    }

    /**
     * @param  factory The {@link org.apache.sshd.common.NamedFactory} for the MAC - ignored if {@code null}
     * @return         The matching {@link org.apache.sshd.common.mac.BuiltinMacs} whose factory name matches (case
     *                 <U>insensitive</U>) the digest factory name
     * @see            #fromFactoryName(String)
     */
    public static BuiltinMacs fromFactory(NamedFactory<Mac> factory) {
        if (factory == null) {
            return null;
        } else {
            return fromFactoryName(factory.getName());
        }
    }

    /**
     * @param  name The factory name - ignored if {@code null}/empty
     * @return      The matching {@link BuiltinMacs} whose factory name matches (case <U>insensitive</U>) the provided
     *              name - {@code null} if no match
     */
    public static BuiltinMacs fromFactoryName(String name) {
        return NamedResource.findByName(name, String.CASE_INSENSITIVE_ORDER, VALUES);
    }

    /**
     * @param  macs A comma-separated list of MACs' names - ignored if {@code null}/empty
     * @return      A {@link ParseResult} containing the successfully parsed factories and the unknown ones.
     *              <B>Note:</B> it is up to caller to ensure that the lists do not contain duplicates
     */
    public static ParseResult parseMacsList(String macs) {
        return parseMacsList(GenericUtils.split(macs, ','));
    }

    public static ParseResult parseMacsList(String... macs) {
        return parseMacsList(GenericUtils.isEmpty((Object[]) macs)
                ? Collections.emptyList()
                : Arrays.asList(macs));
    }

    public static ParseResult parseMacsList(Collection<String> macs) {
        if (GenericUtils.isEmpty(macs)) {
            return ParseResult.EMPTY;
        }

        List<MacFactory> factories = new ArrayList<>(macs.size());
        List<String> unknown = Collections.emptyList();
        for (String name : macs) {
            MacFactory m = resolveFactory(name);
            if (m != null) {
                factories.add(m);
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
    public static MacFactory resolveFactory(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        MacFactory m = fromFactoryName(name);
        if (m != null) {
            return m;
        }

        synchronized (EXTENSIONS) {
            return EXTENSIONS.get(name);
        }
    }

    public static final class ParseResult
            extends NamedFactoriesListParseResult<Mac, MacFactory> {
        public static final ParseResult EMPTY = new ParseResult(Collections.emptyList(), Collections.emptyList());

        public ParseResult(List<MacFactory> parsed, List<String> unsupported) {
            super(parsed, unsupported);
        }
    }

    public static final class Constants {
        public static final String HMAC_MD5 = "hmac-md5";
        public static final String HMAC_MD5_96 = "hmac-md5-96";
        public static final String HMAC_SHA1 = "hmac-sha1";
        public static final String HMAC_SHA1_96 = "hmac-sha1-96";
        public static final String HMAC_SHA2_256 = "hmac-sha2-256";
        public static final String HMAC_SHA2_512 = "hmac-sha2-512";

        public static final String ETM_HMAC_SHA1 = "hmac-sha1-etm@openssh.com";
        public static final String ETM_HMAC_SHA2_256 = "hmac-sha2-256-etm@openssh.com";
        public static final String ETM_HMAC_SHA2_512 = "hmac-sha2-512-etm@openssh.com";

        private Constants() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }
}
