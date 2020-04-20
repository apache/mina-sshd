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

package org.apache.sshd.common.util.security;

import java.security.Provider;
import java.util.Objects;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.threads.ThreadUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SecurityProviderChoice extends NamedResource {
    SecurityProviderChoice EMPTY = new SecurityProviderChoice() {
        @Override
        public String getName() {
            return null;
        }

        @Override
        public boolean isNamedProviderUsed() {
            return false;
        }

        @Override
        public Provider getSecurityProvider() {
            return null;
        }

        @Override
        public String toString() {
            return "EMPTY";
        }
    };

    /**
     * @return {@code true} if to use the provider's name rather than its {@link Provider} instance -
     *         default={@code true}.
     */
    default boolean isNamedProviderUsed() {
        return true;
    }

    /**
     * @return The security {@link Provider} to use in case {@link #isNamedProviderUsed()} is {@code false}. Can be
     *         {@code null} if {@link #isNamedProviderUsed()} is {@code true}, but not recommended.
     */
    Provider getSecurityProvider();

    static SecurityProviderChoice toSecurityProviderChoice(String name) {
        ValidateUtils.checkNotNullAndNotEmpty(name, "No name provided");
        return new SecurityProviderChoice() {
            private final String s = SecurityProviderChoice.class.getSimpleName() + "[" + name + "]";

            @Override
            public String getName() {
                return name;
            }

            @Override
            public boolean isNamedProviderUsed() {
                return true;
            }

            @Override
            public Provider getSecurityProvider() {
                return null;
            }

            @Override
            public String toString() {
                return s;
            }
        };
    }

    static SecurityProviderChoice toSecurityProviderChoice(Provider provider) {
        Objects.requireNonNull(provider, "No provider instance");
        return new SecurityProviderChoice() {
            private final String s = SecurityProviderChoice.class.getSimpleName()
                                     + "[" + Provider.class.getSimpleName() + "]"
                                     + "[" + provider.getName() + "]";

            @Override
            public String getName() {
                return provider.getName();
            }

            @Override
            public boolean isNamedProviderUsed() {
                return false;
            }

            @Override
            public Provider getSecurityProvider() {
                return provider;
            }

            @Override
            public String toString() {
                return s;
            }
        };
    }

    static Provider createProviderInstance(Class<?> anchor, String providerClassName)
            throws ReflectiveOperationException {
        return ThreadUtils.createDefaultInstance(anchor, Provider.class, providerClassName);
    }
}
