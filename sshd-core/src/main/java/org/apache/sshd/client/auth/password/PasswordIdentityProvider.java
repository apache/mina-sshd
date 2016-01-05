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

package org.apache.sshd.client.auth.password;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Supplier;
import org.apache.sshd.common.util.Transformer;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PasswordIdentityProvider {
    PasswordIdentityProvider EMPTY_PASSWORDS_PROVIDER = new PasswordIdentityProvider() {
        @Override
        public Iterable<String> loadPasswords() {
            return Collections.emptyList();
        }

        @Override
        public String toString() {
            return "EMPTY";
        }
    };

    /**
     * @return The currently available passwords - never {@code null}
     */
    Iterable<String> loadPasswords();

    /**
     * A helper class for password identity provider related operations
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    // CHECKSTYLE:OFF
    final class Utils {
    // CHECKSTYLE:ON
        public static final Transformer<PasswordIdentityProvider, Iterable<String>> LOADER =
            new Transformer<PasswordIdentityProvider, Iterable<String>>() {
                @Override
                public Iterable<String> transform(PasswordIdentityProvider p) {
                    return (p == null) ? null : p.loadPasswords();
                }
            };

        private Utils() {
            throw new UnsupportedOperationException("No instance allowed");
        }

        public static Iterator<String> iteratorOf(ClientSession session) {
            ValidateUtils.checkNotNull(session, "No session");
            return iteratorOf(session.getRegisteredIdentities(), session.getPasswordIdentityProvider());
        }

        public static Iterator<String> iteratorOf(PasswordIdentityProvider identities, PasswordIdentityProvider passwords) {
            return iteratorOf(resolvePasswordIdentityProvider(identities, passwords));
        }

        /**
         * Resolves a non-{@code null} iterator of the available passwords
         *
         * @param provider The {@link PasswordIdentityProvider} - ignored if {@code null}
         * @return A non-{@code null} iterator - which may be empty if no provider or no passwords
         */
        public static Iterator<String> iteratorOf(PasswordIdentityProvider provider) {
            return GenericUtils.iteratorOf((provider == null) ? null : provider.loadPasswords());
        }

        public static PasswordIdentityProvider resolvePasswordIdentityProvider(PasswordIdentityProvider identities, PasswordIdentityProvider passwords) {
            if ((passwords == null) || (identities == passwords)) {
                return identities;
            } else if (identities == null) {
                return passwords;
            } else {
                return multiProvider(identities, passwords);
            }
        }

        public static PasswordIdentityProvider multiProvider(PasswordIdentityProvider ... providers) {
            return multiProvider(GenericUtils.isEmpty(providers) ? Collections.<PasswordIdentityProvider>emptyList() : Arrays.asList(providers));
        }

        public static PasswordIdentityProvider multiProvider(Collection<? extends PasswordIdentityProvider> providers) {
            return wrap(iterableOf(providers));
        }

        public static Iterable<String> iterableOf(Collection<? extends PasswordIdentityProvider> providers) {
            if (GenericUtils.isEmpty(providers)) {
                return Collections.emptyList();
            }

            Collection<Supplier<Iterable<String>>> suppliers = new ArrayList<Supplier<Iterable<String>>>(providers.size());
            for (final PasswordIdentityProvider p : providers) {
                if (p == null) {
                    continue;
                }

                suppliers.add(new Supplier<Iterable<String>>() {
                    @Override
                    public Iterable<String> get() {
                        return p.loadPasswords();
                    }
                });
            }

            if (GenericUtils.isEmpty(suppliers)) {
                return Collections.emptyList();
            }

            return GenericUtils.multiIterableSuppliers(suppliers);
        }

        public static PasswordIdentityProvider wrap(final Iterable<String> passwords) {
            return new PasswordIdentityProvider() {
                @Override
                public Iterable<String> loadPasswords() {
                    return passwords;
                }
            };
        }
    }
}
