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

package org.apache.sshd.client;

import java.security.KeyPair;
import java.util.Collection;
import java.util.List;

import org.apache.sshd.client.auth.AuthenticationIdentitiesProvider;
import org.apache.sshd.client.auth.BuiltinUserAuthFactories;
import org.apache.sshd.client.auth.UserAuth;
import org.apache.sshd.client.auth.UserAuthFactory;
import org.apache.sshd.client.auth.hostbased.HostBasedAuthenticationReporter;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.auth.password.PasswordAuthenticationReporter;
import org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.apache.sshd.client.auth.pubkey.PublicKeyAuthenticationReporter;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.auth.UserAuthFactoriesManager;
import org.apache.sshd.common.keyprovider.KeyIdentityProviderHolder;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Holds information required for the client to perform authentication with the server
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ClientAuthenticationManager
        extends UserAuthFactoriesManager<ClientSession, UserAuth, UserAuthFactory>,
        KeyIdentityProviderHolder {

    /**
     * @return The {@link AuthenticationIdentitiesProvider} to be used for attempting password or public key
     *         authentication
     */
    AuthenticationIdentitiesProvider getRegisteredIdentities();

    /**
     * Retrieve {@link PasswordIdentityProvider} used to provide password candidates
     *
     * @return The {@link PasswordIdentityProvider} instance - ignored if {@code null} (i.e., no passwords available).
     * @see    #addPasswordIdentity(String)
     */
    PasswordIdentityProvider getPasswordIdentityProvider();

    void setPasswordIdentityProvider(PasswordIdentityProvider provider);

    /**
     * @param password Password to be added - may not be {@code null}/empty. <B>Note:</B> this password is <U>in
     *                 addition</U> to whatever passwords are available via the {@link PasswordIdentityProvider} (if
     *                 any)
     */
    void addPasswordIdentity(String password);

    /**
     * @param  password The password to remove - ignored if {@code null}/empty
     * @return          The removed password - same one that was added via {@link #addPasswordIdentity(String)} - or
     *                  {@code null} if no match found
     */
    String removePasswordIdentity(String password);

    /**
     * @param key The {@link KeyPair} to add - may not be {@code null} <B>Note:</B> this key is <U>in addition</U> to
     *            whatever keys are available via the {@link org.apache.sshd.common.keyprovider.KeyIdentityProvider} (if
     *            any)
     */
    void addPublicKeyIdentity(KeyPair key);

    /**
     * @param  kp The {@link KeyPair} to remove - ignored if {@code null}
     * @return    The removed {@link KeyPair} - same one that was added via {@link #addPublicKeyIdentity(KeyPair)} - or
     *            {@code null} if no match found
     */
    KeyPair removePublicKeyIdentity(KeyPair kp);

    /**
     * Retrieve the server key verifier to be used to check the key when connecting to an SSH server.
     *
     * @return the {@link ServerKeyVerifier} to use - never {@code null}
     */
    ServerKeyVerifier getServerKeyVerifier();

    void setServerKeyVerifier(ServerKeyVerifier serverKeyVerifier);

    /**
     * @return A {@link UserInteraction} object to communicate with the user (may be {@code null} to indicate that no
     *         such communication is allowed)
     */
    UserInteraction getUserInteraction();

    void setUserInteraction(UserInteraction userInteraction);

    PasswordAuthenticationReporter getPasswordAuthenticationReporter();

    void setPasswordAuthenticationReporter(PasswordAuthenticationReporter reporter);

    PublicKeyAuthenticationReporter getPublicKeyAuthenticationReporter();

    void setPublicKeyAuthenticationReporter(PublicKeyAuthenticationReporter reporter);

    HostBasedAuthenticationReporter getHostBasedAuthenticationReporter();

    void setHostBasedAuthenticationReporter(HostBasedAuthenticationReporter reporter);

    @Override
    default void setUserAuthFactoriesNames(Collection<String> names) {
        BuiltinUserAuthFactories.ParseResult result = BuiltinUserAuthFactories.parseFactoriesList(names);
        List<UserAuthFactory> factories = ValidateUtils.checkNotNullAndNotEmpty(
                result.getParsedFactories(), "No supported user authentication factories: %s", names);
        Collection<String> unsupported = result.getUnsupportedFactories();
        ValidateUtils.checkTrue(
                GenericUtils.isEmpty(unsupported), "Unsupported user authentication factories found: %s", unsupported);
        setUserAuthFactories(factories);
    }
}
