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

package org.apache.sshd.client.auth;

import java.security.KeyPair;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface AuthenticationIdentitiesProvider extends KeyIdentityProvider, PasswordIdentityProvider {
    /**
     * @return All the currently available identities - passwords, keys, etc...
     */
    Iterable<?> loadIdentities();

    /**
     * A helper class for identity provider related operations
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    // CHECKSTYLE:OFF
    final class Utils {
    // CHECKSTYLE:ON
        /**
         * Compares 2 password identities - returns zero ONLY if <U>both</U> compared
         * objects are {@link String}s and equal to each other
         */
        public static final Comparator<Object> PASSWORD_IDENTITY_COMPARATOR = new Comparator<Object>() {
            @Override
            public int compare(Object o1, Object o2) {
                if (!(o1 instanceof String) || !(o2 instanceof String)) {
                    return -1;
                } else {
                    return ((String) o1).compareTo((String) o2);
                }
            }
        };

        /**
         * Compares 2 {@link KeyPair} identities - returns zero ONLY if <U>both</U> compared
         * objects are {@link KeyPair}s and equal to each other
         */
        public static final Comparator<Object> KEYPAIR_IDENTITY_COMPARATOR = new Comparator<Object>() {
            @Override
            public int compare(Object o1, Object o2) {
                if ((!(o1 instanceof KeyPair)) || (!(o2 instanceof KeyPair))) {
                    return -1;
                } else if (KeyUtils.compareKeyPairs((KeyPair) o1, (KeyPair) o2)) {
                    return 0;
                } else {
                    return 1;
                }
            }
        };

        private Utils() {
            throw new UnsupportedOperationException("No instance allowed");
        }

        public static int findIdentityIndex(List<?> identities, Comparator<? super Object> comp, Object target) {
            for (int index = 0; index < identities.size(); index++) {
                Object value = identities.get(index);
                if (comp.compare(value, target) == 0) {
                    return index;
                }
            }

            return -1;
        }

        /**
         * @param identities The {@link Iterable} identities - OK if {@code null}/empty
         * @return An {@link AuthenticationIdentitiesProvider} wrapping the identities
         */
        public static AuthenticationIdentitiesProvider wrap(final Iterable<?> identities) {
            return new AuthenticationIdentitiesProvider() {
                @Override
                public Iterable<KeyPair> loadKeys() {
                    return selectIdentities(KeyPair.class);
                }

                @Override
                public Iterable<String> loadPasswords() {
                    return selectIdentities(String.class);
                }

                @Override
                public Iterable<?> loadIdentities() {
                    return selectIdentities(Object.class);
                }

                // NOTE: returns a NEW Collection on every call so that the original
                //      identities remain unchanged
                private <T> Collection<T> selectIdentities(Class<T> type) {
                    Collection<T> matches = null;
                    for (Iterator<?> iter = GenericUtils.iteratorOf(identities); iter.hasNext();) {
                        Object o = iter.next();
                        Class<?> t = o.getClass();
                        if (!type.isAssignableFrom(t)) {
                            continue;
                        }

                        if (matches == null) {
                            matches = new LinkedList<T>();
                        }

                        matches.add(type.cast(o));
                    }

                    return (matches == null) ? Collections.<T>emptyList() : matches;
                }
            };
        }
    }
}
