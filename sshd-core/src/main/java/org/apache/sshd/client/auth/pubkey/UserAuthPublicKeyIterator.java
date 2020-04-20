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

package org.apache.sshd.client.auth.pubkey;

import java.io.IOException;
import java.nio.channels.Channel;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.signature.SignatureFactoriesManager;
import org.apache.sshd.common.util.helper.LazyIterablesConcatenator;
import org.apache.sshd.common.util.helper.LazyMatchingTypeIterator;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthPublicKeyIterator extends AbstractKeyPairIterator<PublicKeyIdentity> implements Channel {
    private final AtomicBoolean open = new AtomicBoolean(true);
    private Iterator<? extends PublicKeyIdentity> current;
    private SshAgent agent;

    public UserAuthPublicKeyIterator(ClientSession session, SignatureFactoriesManager signatureFactories) throws Exception {
        super(session);

        try {
            Collection<Iterable<? extends PublicKeyIdentity>> identities = new ArrayList<>(2);
            Iterable<? extends PublicKeyIdentity> agentIds = initializeAgentIdentities(session);
            if (agentIds != null) {
                identities.add(agentIds);
            }

            Iterable<? extends PublicKeyIdentity> sessionIds = initializeSessionIdentities(session, signatureFactories);
            if (sessionIds != null) {
                identities.add(sessionIds);
            }

            if (identities.isEmpty()) {
                current = Collections.emptyIterator();
            } else {
                Iterable<? extends PublicKeyIdentity> keys = LazyIterablesConcatenator.lazyConcatenateIterables(identities);
                current = LazyMatchingTypeIterator.lazySelectMatchingTypes(keys.iterator(), PublicKeyIdentity.class);
            }
        } catch (Exception e) {
            try {
                closeAgent();
            } catch (Exception err) {
                e.addSuppressed(err);
            }

            throw e;
        }
    }

    @SuppressWarnings("checkstyle:anoninnerlength")
    protected Iterable<KeyPairIdentity> initializeSessionIdentities(
            ClientSession session, SignatureFactoriesManager signatureFactories) {
        return new Iterable<KeyPairIdentity>() {
            private final String sessionId = session.toString();
            private final AtomicReference<Iterable<KeyPair>> keysHolder = new AtomicReference<>();

            @Override
            public Iterator<KeyPairIdentity> iterator() {
                // Lazy load the keys the 1st time the iterator is called
                if (keysHolder.get() == null) {
                    try {
                        KeyIdentityProvider sessionKeysProvider = ClientSession.providerOf(session);
                        keysHolder.set(sessionKeysProvider.loadKeys(session));
                    } catch (IOException | GeneralSecurityException e) {
                        throw new RuntimeException(
                                "Unexpected " + e.getClass().getSimpleName() + ")"
                                                   + " keys loading exception: " + e.getMessage(),
                                e);
                    }
                }

                return new Iterator<KeyPairIdentity>() {
                    private final Iterator<KeyPair> keys;

                    {
                        @SuppressWarnings("synthetic-access")
                        Iterable<KeyPair> sessionKeys = Objects.requireNonNull(keysHolder.get(), "No session keys available");
                        keys = sessionKeys.iterator();
                    }

                    @Override
                    public boolean hasNext() {
                        return keys.hasNext();
                    }

                    @Override
                    public KeyPairIdentity next() {
                        KeyPair kp = keys.next();
                        return new KeyPairIdentity(signatureFactories, session, kp);
                    }

                    @Override
                    @SuppressWarnings("synthetic-access")
                    public String toString() {
                        return KeyPairIdentity.class.getSimpleName() + "[iterator][" + sessionId + "]";
                    }
                };
            }

            @Override
            public String toString() {
                return KeyPairIdentity.class.getSimpleName() + "[iterable][" + sessionId + "]";
            }
        };
    }

    protected Iterable<KeyAgentIdentity> initializeAgentIdentities(ClientSession session) throws IOException {
        FactoryManager manager = Objects.requireNonNull(session.getFactoryManager(), "No session factory manager");
        SshAgentFactory factory = manager.getAgentFactory();
        if (factory == null) {
            return null;
        }

        agent = Objects.requireNonNull(factory.createClient(manager), "No agent created");
        return new Iterable<KeyAgentIdentity>() {
            @SuppressWarnings("synthetic-access")
            private final Iterable<? extends Map.Entry<PublicKey, String>> agentIds = agent.getIdentities();
            @SuppressWarnings("synthetic-access")
            private final String agentId = agent.toString();

            @Override
            public Iterator<KeyAgentIdentity> iterator() {
                return new Iterator<KeyAgentIdentity>() {
                    @SuppressWarnings("synthetic-access")
                    private final Iterator<? extends Map.Entry<PublicKey, String>> iter = agentIds.iterator();

                    @Override
                    public boolean hasNext() {
                        return iter.hasNext();
                    }

                    @Override
                    @SuppressWarnings("synthetic-access")
                    public KeyAgentIdentity next() {
                        Map.Entry<PublicKey, String> kp = iter.next();
                        return new KeyAgentIdentity(agent, kp.getKey(), kp.getValue());
                    }

                    @Override
                    @SuppressWarnings("synthetic-access")
                    public String toString() {
                        return KeyAgentIdentity.class.getSimpleName() + "[iterator][" + agentId + "]";
                    }
                };
            }

            @Override
            public String toString() {
                return KeyAgentIdentity.class.getSimpleName() + "[iterable][" + agentId + "]";
            }
        };
    }

    @Override
    public boolean hasNext() {
        if (!isOpen()) {
            return false;
        }

        return current.hasNext();
    }

    @Override
    public PublicKeyIdentity next() {
        if (!isOpen()) {
            throw new NoSuchElementException("Iterator is closed");
        }
        return current.next();
    }

    @Override
    public boolean isOpen() {
        return open.get();
    }

    @Override
    public void close() throws IOException {
        if (open.getAndSet(false)) {
            closeAgent();
        }
    }

    protected void closeAgent() throws IOException {
        if (agent != null) {
            try {
                agent.close();
            } finally {
                agent = null;
            }
        }
    }

}
