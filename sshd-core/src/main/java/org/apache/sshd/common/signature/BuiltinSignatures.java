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

package org.apache.sshd.common.signature;

import java.security.spec.ECParameterSpec;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.common.Digest;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.Signature;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.SecurityUtils;

/**
 * Provides easy access to the currently implemented macs
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinSignatures implements NamedFactory<Signature>, OptionalFeature {
    dsa(KeyPairProvider.SSH_DSS) {
        @Override
        public Signature create() {
            return new SignatureDSA("SHA1withDSA");
        }
    },
    rsa(KeyPairProvider.SSH_RSA) {
        @Override
        public Signature create() {
            return new SignatureRSA();
        }
    },
    nistp256(KeyPairProvider.ECDSA_SHA2_NISTP256) {
        @Override
        public Signature create() {
            return new SignatureECDSA("SHA256withECDSA");
        }
        
        @Override
        public boolean isSupported() {
            return SecurityUtils.isBouncyCastleRegistered() || SecurityUtils.hasEcc();
        }
    },
    nistp384(KeyPairProvider.ECDSA_SHA2_NISTP384) {
        @Override
        public Signature create() {
            return new SignatureECDSA("SHA384withECDSA");
        }
        
        @Override
        public boolean isSupported() {
            return SecurityUtils.isBouncyCastleRegistered() || SecurityUtils.hasEcc();
        }
    },
    nistp521(KeyPairProvider.ECDSA_SHA2_NISTP521) {
        @Override
        public Signature create() {
            return new SignatureECDSA("SHA512withECDSA");
        }
        
        @Override
        public boolean isSupported() {
            return SecurityUtils.isBouncyCastleRegistered() || SecurityUtils.hasEcc();
        }
    };

    private final String factoryName;

    public static Signature getByCurveSize(ECParameterSpec params) {
        int curveSize = ECCurves.getCurveSize(params);
        if (curveSize <= 256) {
            return nistp256.create();
        } else if (curveSize <= 384) {
            return nistp384.create();
        } else {
            return nistp521.create();
        }
    }

    @Override
    public final String getName() {
        return factoryName;
    }

    BuiltinSignatures(String facName) {
        factoryName = facName;
    }

    @Override
    public boolean isSupported() {
        return true;
    }

    public static final Set<BuiltinSignatures> VALUES =
            Collections.unmodifiableSet(EnumSet.allOf(BuiltinSignatures.class));

    /**
     * @param s The {@link Enum}'s name - ignored if {@code null}/empty
     * @return The matching {@link org.apache.sshd.common.signature.BuiltinSignatures} whose {@link Enum#name()} matches
     * (case <U>insensitive</U>) the provided argument - {@code null} if no match
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
     * @param factory The {@link org.apache.sshd.common.NamedFactory} for the cipher - ignored if {@code null}
     * @return The matching {@link org.apache.sshd.common.signature.BuiltinSignatures} whose factory name matches
     * (case <U>insensitive</U>) the digest factory name
     * @see #fromFactoryName(String)
     */
    public static BuiltinSignatures fromFactory(NamedFactory<Digest> factory) {
        if (factory == null) {
            return null;
        } else {
            return fromFactoryName(factory.getName());
        }
    }

    /**
     * @param n The factory name - ignored if {@code null}/empty
     * @return The matching {@link org.apache.sshd.common.signature.BuiltinSignatures} whose factory name matches
     * (case <U>insensitive</U>) the provided name - {@code null} if no match
     */
    public static BuiltinSignatures fromFactoryName(String n) {
        if (GenericUtils.isEmpty(n)) {
            return null;
        }

        for (BuiltinSignatures c : VALUES) {
            if (n.equalsIgnoreCase(c.getName())) {
                return c;
            }
        }

        return null;
    }
}
