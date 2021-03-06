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
package org.apache.sshd.agent.local;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * A local SSH agent implementation
 */
public class AgentImpl implements SshAgent {
    private final List<Map.Entry<KeyPair, String>> keys = new ArrayList<>();
    private final AtomicBoolean open = new AtomicBoolean(true);

    public AgentImpl() {
        super();
    }

    @Override
    public boolean isOpen() {
        return open.get();
    }

    @Override
    public Iterable<? extends Map.Entry<PublicKey, String>> getIdentities() throws IOException {
        if (!isOpen()) {
            throw new SshException("Agent closed");
        }

        return GenericUtils.map(keys, kp -> new SimpleImmutableEntry<>(kp.getKey().getPublic(), kp.getValue()));
    }

    @Override
    public Map.Entry<String, byte[]> sign(SessionContext session, PublicKey key, String algo, byte[] data) throws IOException {
        if (!isOpen()) {
            throw new SshException("Agent closed");
        }

        try {
            Map.Entry<KeyPair, String> pp = Objects.requireNonNull(getKeyPair(keys, key), "Key not found");
            String agentName = pp.getValue();
            KeyPair kp = ValidateUtils.checkNotNull(pp.getKey(), "No key pair for agent=%s", agentName);
            PublicKey pubKey = ValidateUtils.checkNotNull(kp.getPublic(), "No public key for agent=%s", agentName);
            NamedFactory<Signature> factory = SignatureFactory.resolveSignatureFactoryByPublicKey(pubKey, algo);
            Signature verif = (factory == null) ? null : factory.create();
            if (verif == null) {
                throw new InvalidKeySpecException(
                        "No signer found for " + pubKey.getClass().getSimpleName()
                                                  + " when algorithm=" + algo + " requested for "
                                                  + KeyUtils.getKeyType(pubKey));
            }
            verif.initSigner(session, kp.getPrivate());
            verif.update(session, data);

            byte[] signature = verif.sign(session);
            return new SimpleImmutableEntry<>(factory.getName(), signature);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new SshException(e);
        }
    }

    @Override
    public void addIdentity(KeyPair key, String comment) throws IOException {
        if (!isOpen()) {
            throw new SshException("Agent closed");
        }
        keys.add(new SimpleImmutableEntry<>(Objects.requireNonNull(key, "No key"), comment));
    }

    @Override
    public KeyPair resolveLocalIdentity(PublicKey key) {
        Map.Entry<KeyPair, String> pp = getKeyPair(keys, key);
        return (pp == null) ? null : pp.getKey();
    }

    @Override
    public void removeIdentity(PublicKey key) throws IOException {
        if (!isOpen()) {
            throw new SshException("Agent closed");
        }

        Map.Entry<KeyPair, String> kp = getKeyPair(keys, key);
        if (kp == null) {
            throw new SshException("Key not found");
        }
        keys.remove(kp);
    }

    @Override
    public void removeAllIdentities() throws IOException {
        if (!isOpen()) {
            throw new SshException("Agent closed");
        }
        keys.clear();
    }

    @Override
    public void close() throws IOException {
        if (open.getAndSet(false)) {
            keys.clear();
        }
    }

    protected static Map.Entry<KeyPair, String> getKeyPair(
            Collection<? extends Map.Entry<KeyPair, String>> keys, PublicKey key) {
        if (GenericUtils.isEmpty(keys) || (key == null)) {
            return null;
        }

        for (Map.Entry<KeyPair, String> k : keys) {
            KeyPair kp = k.getKey();
            if (KeyUtils.compareKeys(key, kp.getPublic())) {
                return k;
            }
        }

        return null;
    }
}
