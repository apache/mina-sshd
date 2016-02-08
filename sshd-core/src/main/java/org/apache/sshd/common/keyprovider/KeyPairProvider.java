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
package org.apache.sshd.common.keyprovider;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.GenericUtils;

/**
 * Provider for key pairs.  This provider is used on the server side to provide
 * the host key, or on the client side to provide the user key.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface KeyPairProvider extends KeyIdentityProvider {

    /**
     * SSH identifier for RSA keys
     */
    String SSH_RSA = "ssh-rsa";

    /**
     * SSH identifier for DSA keys
     */
    String SSH_DSS = "ssh-dss";

    /**
     * SSH identifier for ED25519 elliptic curve keys
     */
    String SSH_ED25519 = "ssh-ed25519";

    /**
     * SSH identifier for EC keys in NIST curve P-256
     */
    String ECDSA_SHA2_NISTP256 = ECCurves.nistp256.getKeyType();

    /**
     * SSH identifier for EC keys in NIST curve P-384
     */
    String ECDSA_SHA2_NISTP384 = ECCurves.nistp384.getKeyType();

    /**
     * SSH identifier for EC keys in NIST curve P-521
     */
    String ECDSA_SHA2_NISTP521 = ECCurves.nistp521.getKeyType();

    /**
     * A {@link KeyPairProvider} that has no keys
     */
    KeyPairProvider EMPTY_KEYPAIR_PROVIDER =
        new KeyPairProvider() {
            @Override
            public KeyPair loadKey(String type) {
                return null;
            }

            @Override
            public Iterable<String> getKeyTypes() {
                return Collections.emptyList();
            }

            @Override
            public Iterable<KeyPair> loadKeys() {
                return Collections.emptyList();
            }

            @Override
            public String toString() {
                return "EMPTY_KEYPAIR_PROVIDER";
            }
        };

    /**
     * Load a key of the specified type which can be &quot;ssh-rsa&quot;, &quot;ssh-dss&quot;,
     * or &quot;ecdsa-sha2-nistp{256,384,521}&quot;. If there is no key of this type, return
     * {@code null}
     *
     * @param type the type of key to load
     * @return a valid key pair or {@code null} if this type of key is not available
     */
    KeyPair loadKey(String type);

    /**
     * @return The available {@link Iterable} key types in preferred order - never {@code null}
     */
    Iterable<String> getKeyTypes();

    /**
     * A helper class for key-pair providers
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    // CHECKSTYLE:OFF
    final class Utils {
    // CHECKSTYLE:ON
        private Utils() {
            throw new UnsupportedOperationException("No instance allowed");
        }

        /**
         * Wrap the provided {@link KeyPair}s into a {@link KeyPairProvider}
         *
         * @param pairs The available pairs - ignored if {@code null}/empty (i.e.,
         * returns {@link #EMPTY_KEYPAIR_PROVIDER})
         * @return The provider wrapper
         * @see #wrap(Iterable)
         */
        public static KeyPairProvider wrap(KeyPair ... pairs) {
            return GenericUtils.isEmpty(pairs) ? EMPTY_KEYPAIR_PROVIDER : wrap(Arrays.asList(pairs));
        }

        /**
         * Wrap the provided {@link KeyPair}s into a {@link KeyPairProvider}
         *
         * @param pairs The available pairs {@link Iterable} - ignored if {@code null} (i.e.,
         * returns {@link #EMPTY_KEYPAIR_PROVIDER})
         * @return The provider wrapper
         */
        public static KeyPairProvider wrap(final Iterable<KeyPair> pairs) {
            return (pairs == null) ? EMPTY_KEYPAIR_PROVIDER : new KeyPairProvider() {
                @Override
                public Iterable<KeyPair> loadKeys() {
                    return pairs;
                }

                @Override
                public KeyPair loadKey(String type) {
                    for (KeyPair kp : pairs) {
                        String t = KeyUtils.getKeyType(kp);
                        if (Objects.equals(type, t)) {
                            return kp;
                        }
                    }

                    return null;
                }

                @Override
                public Iterable<String> getKeyTypes() {
                    // use a LinkedHashSet so as to preserve the order but avoid duplicates
                    Collection<String> types = new LinkedHashSet<>();
                    for (KeyPair kp : pairs) {
                        String t = KeyUtils.getKeyType(kp);
                        if (GenericUtils.isEmpty(t)) {
                            continue;   // avoid unknown key types
                        }

                        if (!types.add(t)) {
                            continue;   // debug breakpoint
                        }
                    }

                    return types;
                }
            };
        }
    }
}
