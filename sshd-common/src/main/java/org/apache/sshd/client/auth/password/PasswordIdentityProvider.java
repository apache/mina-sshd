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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.function.Supplier;

import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface PasswordIdentityProvider {

    /**
     * An &quot;empty&quot implementation of {@link PasswordIdentityProvider} that returns an empty group of passwords
     */
    PasswordIdentityProvider EMPTY_PASSWORDS_PROVIDER = new PasswordIdentityProvider() {
        @Override
        public Iterable<String> loadPasswords(SessionContext session)
                throws IOException, GeneralSecurityException {
            return Collections.emptyList();
        }

        @Override
        public String toString() {
            return "EMPTY";
        }
    };

    /**
     * @param  session                  The {@link SessionContext} for invoking this load command - may be {@code null}
     *                                  if not invoked within a session context (e.g., offline tool).
     * @return                          The currently available passwords - ignored if {@code null}
     * @throws IOException              If failed to load the passwords
     * @throws GeneralSecurityException If some security issue with the passwords
     */
    Iterable<String> loadPasswords(SessionContext session)
            throws IOException, GeneralSecurityException;

    /**
     * Creates a &quot;unified&quot; {@link Iterator} of passwords out of 2 possible {@link PasswordIdentityProvider}
     *
     * @param  session                  The {@link SessionContext} for invoking this load command - may be {@code null}
     *                                  if not invoked within a session context (e.g., offline tool).
     * @param  identities               The registered passwords
     * @param  passwords                Extra available passwords
     * @return                          The wrapping iterator
     * @throws IOException              If failed to load the passwords
     * @throws GeneralSecurityException If some security issue with the passwords
     * @see                             #resolvePasswordIdentityProvider(SessionContext, PasswordIdentityProvider,
     *                                  PasswordIdentityProvider)
     */
    static Iterator<String> iteratorOf(
            SessionContext session, PasswordIdentityProvider identities, PasswordIdentityProvider passwords)
            throws IOException, GeneralSecurityException {
        return iteratorOf(session, resolvePasswordIdentityProvider(session, identities, passwords));
    }

    /**
     * Resolves a non-{@code null} iterator of the available passwords
     *
     * @param  session                  The {@link SessionContext} for invoking this load command - may be {@code null}
     *                                  if not invoked within a session context (e.g., offline tool).
     * @param  provider                 The {@link PasswordIdentityProvider} - ignored if {@code null} (i.e., return an
     *                                  empty iterator)
     * @return                          A non-{@code null} iterator - which may be empty if no provider or no passwords
     * @throws IOException              If failed to load the passwords
     * @throws GeneralSecurityException If some security issue with the passwords
     */
    static Iterator<String> iteratorOf(SessionContext session, PasswordIdentityProvider provider)
            throws IOException, GeneralSecurityException {
        return GenericUtils.iteratorOf((provider == null) ? null : provider.loadPasswords(session));
    }

    /**
     * <P>
     * Creates a &quot;unified&quot; {@link PasswordIdentityProvider} out of 2 possible ones as follows:
     * </P>
     * </BR>
     * <UL>
     * <LI>If both are {@code null} then return {@code null}.</LI>
     * <LI>If either one is {@code null} then use the non-{@code null} one.</LI>
     * <LI>If both are the same instance then use it.</U>
     * <LI>Otherwise, returns a wrapper that groups both providers.</LI>
     * </UL>
     *
     * @param  session    The {@link SessionContext} for invoking this load command - may be {@code null} if not invoked
     *                    within a session context (e.g., offline tool).
     * @param  identities The registered passwords
     * @param  passwords  The extra available passwords
     * @return            The resolved provider
     * @see               #multiProvider(SessionContext, PasswordIdentityProvider...)
     */
    static PasswordIdentityProvider resolvePasswordIdentityProvider(
            SessionContext session, PasswordIdentityProvider identities, PasswordIdentityProvider passwords) {
        if ((passwords == null) || (identities == passwords)) {
            return identities;
        } else if (identities == null) {
            return passwords;
        } else {
            return multiProvider(session, identities, passwords);
        }
    }

    /**
     * Wraps a group of {@link PasswordIdentityProvider} into a single one
     *
     * @param  session   The {@link SessionContext} for invoking this load command - may be {@code null} if not invoked
     *                   within a session context (e.g., offline tool).
     * @param  providers The providers - ignored if {@code null}/empty (i.e., returns {@link #EMPTY_PASSWORDS_PROVIDER}
     * @return           The wrapping provider
     * @see              #multiProvider(SessionContext, Collection)
     */
    static PasswordIdentityProvider multiProvider(
            SessionContext session, PasswordIdentityProvider... providers) {
        return multiProvider(session, GenericUtils.asList(providers));
    }

    /**
     * Wraps a group of {@link PasswordIdentityProvider} into a single one
     *
     * @param  session   The {@link SessionContext} for invoking this load command - may be {@code null} if not invoked
     *                   within a session context (e.g., offline tool).
     * @param  providers The providers - ignored if {@code null}/empty (i.e., returns {@link #EMPTY_PASSWORDS_PROVIDER}
     * @return           The wrapping provider
     */
    static PasswordIdentityProvider multiProvider(
            SessionContext session, Collection<? extends PasswordIdentityProvider> providers) {
        return GenericUtils.isEmpty(providers) ? EMPTY_PASSWORDS_PROVIDER : wrapPasswords(iterableOf(session, providers));
    }

    /**
     * Wraps a group of {@link PasswordIdentityProvider} into an {@link Iterable} of their combined passwords
     *
     * @param  session   The {@link SessionContext} for invoking this load command - may be {@code null} if not invoked
     *                   within a session context (e.g., offline tool).
     * @param  providers The providers - ignored if {@code null}/empty (i.e., returns an empty iterable instance)
     * @return           The wrapping iterable
     */
    static Iterable<String> iterableOf(
            SessionContext session, Collection<? extends PasswordIdentityProvider> providers) {
        Iterable<Supplier<Iterable<String>>> passwordSuppliers
                = GenericUtils.<PasswordIdentityProvider, Supplier<Iterable<String>>> wrapIterable(
                        providers, p -> () -> {
                            try {
                                return p.loadPasswords(session);
                            } catch (IOException | GeneralSecurityException e) {
                                throw new RuntimeException(e);
                            }
                        });
        return GenericUtils.multiIterableSuppliers(passwordSuppliers);
    }

    /**
     * Wraps a group of passwords into a {@link PasswordIdentityProvider}
     *
     * @param  passwords The passwords - ignored if {@code null}/empty (i.e., returns {@link #EMPTY_PASSWORDS_PROVIDER})
     * @return           The provider wrapper
     */
    static PasswordIdentityProvider wrapPasswords(String... passwords) {
        return wrapPasswords(GenericUtils.asList(passwords));
    }

    /**
     * Wraps a group of passwords into a {@link PasswordIdentityProvider}
     *
     * @param  passwords The passwords {@link Iterable} - ignored if {@code null} (i.e., returns
     *                   {@link #EMPTY_PASSWORDS_PROVIDER})
     * @return           The provider wrapper
     */
    static PasswordIdentityProvider wrapPasswords(Iterable<String> passwords) {
        return (passwords == null) ? EMPTY_PASSWORDS_PROVIDER : session -> passwords;
    }
}
