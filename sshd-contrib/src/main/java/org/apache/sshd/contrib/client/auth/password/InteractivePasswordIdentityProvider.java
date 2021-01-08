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
package org.apache.sshd.contrib.client.auth.password;

import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionHolder;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.GenericUtils;

/**
 * <P>
 * Helps implement a {@link PasswordIdentityProvider} by delegating calls to
 * {@link UserInteraction#getUpdatedPassword(ClientSession, String, String)}. The way to use it would be as follows:
 * </P>
 * 
 * <pre>
 * <code>
 * try (ClientSession session = client.connect(login, host, port).await().getSession()) {
 *     session.setUserInteraction(...);     // this can also be set at the client level
 *     PasswordIdentityProvider passwordIdentityProvider =
 *          InteractivePasswordIdentityProvider.providerOf(session, "My prompt");
 *     session.setPasswordIdentityProvider(passwordIdentityProvider);
 *     session.auth.verify(...timeout...);
 * }
 *
 * or
 *
 * UserInteraction ui = ....;
 * try (ClientSession session = client.connect(login, host, port).await().getSession()) {
 *     PasswordIdentityProvider passwordIdentityProvider =
 *          InteractivePasswordIdentityProvider.providerOf(session, ui, "My prompt");
 *     session.setPasswordIdentityProvider(passwordIdentityProvider);
 *     session.auth.verify(...timeout...);
 * }
 * </code>
 * </pre>
 *
 * <B>Note:</B> {@link UserInteraction#isInteractionAllowed(ClientSession)} is consulted prior to invoking
 * {@code getUpdatedPassword} - if returns {@code false} then password retrieval method is not invoked, and it is
 * assumed that no more passwords are available
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class InteractivePasswordIdentityProvider
        implements Iterator<String>, SessionHolder<ClientSession>, ClientSessionHolder {
    /** Special marker to indicate that we exhausted all attempts */
    protected static final String EOF = "EOF";

    private ClientSession clientSession;
    private UserInteraction userInteraction;
    private String prompt;
    private AtomicReference<String> nextPassword = new AtomicReference<>();

    public InteractivePasswordIdentityProvider(
                                               ClientSession clientSession, UserInteraction userInteraction, String prompt) {
        this.clientSession = Objects.requireNonNull(clientSession, "No client session provided");
        this.userInteraction = Objects.requireNonNull(userInteraction, "No user interaction instance configured");
        this.prompt = prompt;
    }

    @Override
    public ClientSession getClientSession() {
        return clientSession;
    }

    @Override
    public ClientSession getSession() {
        return getClientSession();
    }

    public UserInteraction getUserInteraction() {
        return userInteraction;
    }

    public String getPrompt() {
        return prompt;
    }

    @Override
    public boolean hasNext() {
        String password = nextPassword.get();
        if (GenericUtils.isEmpty(password)) {
            password = resolveNextPassword();
            if (GenericUtils.isEmpty(password)) {
                password = EOF;
            }
            nextPassword.set(password);
        }

        return !GenericUtils.isSameReference(password, EOF);
    }

    @Override
    public String next() {
        String password = nextPassword.get();
        if (password == null) {
            throw new IllegalStateException("hasNext() not called before next()");
        }

        if (GenericUtils.isSameReference(password, EOF)) {
            throw new NoSuchElementException("All passwords exhausted");
        }

        nextPassword.set(null); // force read of next password when 'hasNext' invoked
        return password;
    }

    protected String resolveNextPassword() {
        ClientSession session = getClientSession();
        UserInteraction ui = getUserInteraction();
        if (!ui.isInteractionAllowed(session)) {
            return null;
        }

        return ui.getUpdatedPassword(session, getPrompt(), "");
    }

    public static PasswordIdentityProvider providerOf(ClientSession clientSession, String prompt) {
        return providerOf(clientSession, (clientSession == null) ? null : clientSession.getUserInteraction(), prompt);
    }

    public static PasswordIdentityProvider providerOf(
            ClientSession clientSession, UserInteraction userInteraction, String prompt) {
        Objects.requireNonNull(clientSession, "No client session provided");
        Objects.requireNonNull(userInteraction, "No user interaction instance configured");
        Iterable<String> passwords = () -> new InteractivePasswordIdentityProvider(clientSession, userInteraction, prompt);
        return () -> passwords;
    }
}
