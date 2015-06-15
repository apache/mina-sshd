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

package org.apache.sshd.common.digest;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.util.GenericUtils;

/**
 * Provides easy access to the currently implemented digests
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinDigests implements DigestInformation, NamedFactory<Digest> {
    md5(Constants.MD5, "MD5", 16),
    sha1(Constants.SHA1, "SHA-1", 20),
    sha256(Constants.SHA256, "SHA-256", 32),
    sha384(Constants.SHA384, "SHA-384", 48),
    sha512(Constants.SHA512, "SHA-512", 64);

    private final String algorithm;
    private final int blockSize;
    private final String factoryName;

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
        return blockSize;
    }

    @Override
    public final String toString() {
        return getName();
    }

    @Override
    public final Digest create() {
        return new BaseDigest(getAlgorithm(), getBlockSize());
    }

    BuiltinDigests(String factoryName, String algorithm, int blockSize) {
        this.factoryName = factoryName;
        this.algorithm = algorithm;
        this.blockSize = blockSize;
    }

    public static final Set<BuiltinDigests> VALUES =
            Collections.unmodifiableSet(EnumSet.allOf(BuiltinDigests.class));

    /**
     * @param s The {@link Enum}'s name - ignored if {@code null}/empty
     * @return The matching {@link org.apache.sshd.common.digest.BuiltinDigests} whose {@link Enum#name()} matches
     * (case <U>insensitive</U>) the provided argument - {@code null} if no match
     */
    public static BuiltinDigests fromString(String s) {
        if (GenericUtils.isEmpty(s)) {
            return null;
        }

        for (BuiltinDigests c : VALUES) {
            if (s.equalsIgnoreCase(c.name())) {
                return c;
            }
        }

        return null;
    }

    /**
     * @param factory The {@link org.apache.sshd.common.NamedFactory} for the cipher - ignored if {@code null}
     * @return The matching {@link org.apache.sshd.common.digest.BuiltinDigests} whose factory name matches
     * (case <U>insensitive</U>) the digest factory name
     * @see #fromFactoryName(String)
     */
    public static BuiltinDigests fromFactory(NamedFactory<Digest> factory) {
        if (factory == null) {
            return null;
        } else {
            return fromFactoryName(factory.getName());
        }
    }

    /**
     * @param n The factory name - ignored if {@code null}/empty
     * @return The matching {@link org.apache.sshd.common.digest.BuiltinDigests} whose factory name matches
     * (case <U>insensitive</U>) the provided name - {@code null} if no match
     */
    public static BuiltinDigests fromFactoryName(String n) {
        if (GenericUtils.isEmpty(n)) {
            return null;
        }

        for (BuiltinDigests c : VALUES) {
            if (n.equalsIgnoreCase(c.getName())) {
                return c;
            }
        }

        return null;
    }

    public static final class Constants {
        public static final String MD5 = "md5";
        public static final String SHA1 = "sha1";
        public static final String SHA256 = "sha256";
        public static final String SHA384 = "sha384";
        public static final String SHA512 = "sha512";
    }
}
