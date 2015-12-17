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
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Pair;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * A local SSH agent implementation
 */
public class AgentImpl implements SshAgent {

    private final List<Pair<KeyPair, String>> keys = new ArrayList<>();
    private final AtomicBoolean open = new AtomicBoolean(true);

    public AgentImpl() {
        super();
    }

    @Override
    public boolean isOpen() {
        return open.get();
    }

    @Override
    public List<Pair<PublicKey, String>> getIdentities() throws IOException {
        if (!isOpen()) {
            throw new SshException("Agent closed");
        }

        List<Pair<PublicKey, String>> pks = new ArrayList<>();
        for (Pair<KeyPair, String> kp : keys) {
            pks.add(new Pair<>(kp.getFirst().getPublic(), kp.getSecond()));
        }
        return pks;
    }

    @Override
    public byte[] sign(PublicKey key, byte[] data) throws IOException {
        if (!isOpen()) {
            throw new SshException("Agent closed");
        }

        try {
            Pair<KeyPair, String> pp = ValidateUtils.checkNotNull(getKeyPair(keys, key), "Key not found");
            KeyPair kp = ValidateUtils.checkNotNull(pp.getFirst(), "No key pair for agent=%s", pp.getSecond());
            PublicKey pubKey = ValidateUtils.checkNotNull(kp.getPublic(), "No public key for agent=%s", pp.getSecond());

            final Signature verif;
            if (pubKey instanceof DSAPublicKey) {
                verif = BuiltinSignatures.dsa.create();
            } else if (pubKey instanceof ECPublicKey) {
                ECPublicKey ecKey = (ECPublicKey) pubKey;
                verif = BuiltinSignatures.getByCurveSize(ecKey.getParams());
            } else if (pubKey instanceof RSAPublicKey) {
                verif = BuiltinSignatures.rsa.create();
            } else {
                throw new SshException("Unsupported key type: " + pubKey.getClass().getSimpleName());
            }
            verif.initSigner(kp.getPrivate());
            verif.update(data);
            return verif.sign();
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
        keys.add(new Pair<>(ValidateUtils.checkNotNull(key, "No key"), comment));
    }

    @Override
    public void removeIdentity(PublicKey key) throws IOException {
        if (!isOpen()) {
            throw new SshException("Agent closed");
        }

        Pair<KeyPair, String> kp = getKeyPair(keys, key);
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

    protected static Pair<KeyPair, String> getKeyPair(Collection<Pair<KeyPair, String>> keys, PublicKey key) {
        if (GenericUtils.isEmpty(keys) || (key == null)) {
            return null;
        }

        for (Pair<KeyPair, String> k : keys) {
            KeyPair kp = k.getFirst();
            if (KeyUtils.compareKeys(key, kp.getPublic())) {
                return k;
            }
        }

        return null;
    }
}
