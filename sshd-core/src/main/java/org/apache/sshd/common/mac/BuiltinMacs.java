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

package org.apache.sshd.common.mac;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.common.Digest;
import org.apache.sshd.common.Mac;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.util.GenericUtils;

/**
 * Provides easy access to the currently implemented macs
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinMacs implements NamedFactory<Mac>, OptionalFeature {
    hmacmd5(Constants.HMAC_MD5) {
        @Override
        public Mac create() {
            return new BaseMac("HmacMD5", 16, 16);
        }
    },
    hmacmd596(Constants.HMAC_MD5_96) {
        @Override
        public Mac create() {
            return new BaseMac("HmacMD5", 12, 16);
        }
    },
    hmacsha1(Constants.HMAC_SHA1) {
        @Override
        public Mac create() {
            return new BaseMac("HmacSHA1", 20, 20);
        }
    },
    hmacsha196(Constants.HMAC_SHA1_96) {
        @Override
        public Mac create() {
            return new BaseMac("HmacSHA1", 12, 20);
        }
    },
    hmacsha256(Constants.HMAC_SHA2_256) {
        @Override
        public Mac create() {
            return new BaseMac("HmacSHA256", 32, 32);
        }
    },
    hmacsha512(Constants.HMAC_SHA2_512) {
        @Override
        public Mac create() {
            return new BaseMac("HmacSHA1", 64, 64);
        }
    };

    private final String factoryName;

    @Override
    public final String getName() {
        return factoryName;
    }

    @Override
    public final boolean isSupported() {
        return true;
    }

    BuiltinMacs(String facName) {
        factoryName = facName;
    }

    public static final Set<BuiltinMacs> VALUES =
            Collections.unmodifiableSet(EnumSet.allOf(BuiltinMacs.class));

    /**
     * @param s The {@link Enum}'s name - ignored if {@code null}/empty
     * @return The matching {@link org.apache.sshd.common.mac.BuiltinMacs} whose {@link Enum#name()} matches
     * (case <U>insensitive</U>) the provided argument - {@code null} if no match
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
     * @param factory The {@link org.apache.sshd.common.NamedFactory} for the cipher - ignored if {@code null}
     * @return The matching {@link org.apache.sshd.common.mac.BuiltinMacs} whose factory name matches
     * (case <U>insensitive</U>) the digest factory name
     * @see #fromFactoryName(String)
     */
    public static BuiltinMacs fromFactory(NamedFactory<Digest> factory) {
        if (factory == null) {
            return null;
        } else {
            return fromFactoryName(factory.getName());
        }
    }

    /**
     * @param n The factory name - ignored if {@code null}/empty
     * @return The matching {@link org.apache.sshd.common.mac.BuiltinMacs} whose factory name matches
     * (case <U>insensitive</U>) the provided name - {@code null} if no match
     */
    public static BuiltinMacs fromFactoryName(String n) {
        if (GenericUtils.isEmpty(n)) {
            return null;
        }

        for (BuiltinMacs c : VALUES) {
            if (n.equalsIgnoreCase(c.getName())) {
                return c;
            }
        }

        return null;
    }

    public static final class Constants {
        public static final String HMAC_MD5 = "hmac-md5";
        public static final String HMAC_MD5_96 = "hmac-md5-96";
        public static final String HMAC_SHA1 = "hmac-sha1";
        public static final String HMAC_SHA1_96 = "hmac-sha1-96";
        public static final String HMAC_SHA2_256 = "hmac-sha2-256";
        public static final String HMAC_SHA2_512 = "hmac-sha2-512";
    }
}
