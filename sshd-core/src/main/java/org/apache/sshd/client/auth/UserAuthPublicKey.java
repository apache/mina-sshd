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

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.client.auth.pubkey.KeyAgentIdentity;
import org.apache.sshd.client.auth.pubkey.KeyPairIdentity;
import org.apache.sshd.client.auth.pubkey.PublicKeyIdentity;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.Pair;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthPublicKey extends AbstractUserAuth {
    public static final String NAME = UserAuthPublicKeyFactory.NAME;

    private SshAgent agent;
    private Iterator<PublicKeyIdentity> keys;
    private PublicKeyIdentity current;

    public UserAuthPublicKey() {
        super(NAME);
    }

    @Override
    public void init(ClientSession session, String service, Collection<?> identities) throws Exception {
        super.init(session, service, identities);

        List<PublicKeyIdentity> ids = new ArrayList<>();
        for (Object o : identities) {
            if (o instanceof KeyPair) {
                ids.add(new KeyPairIdentity(session.getFactoryManager(), (KeyPair) o));
            }
        }

        FactoryManager manager = session.getFactoryManager();
        SshAgentFactory factory = manager.getAgentFactory();
        if (factory != null) {
            this.agent = factory.createClient(manager);
            for (Pair<PublicKey, String> pair : agent.getIdentities()) {
                ids.add(new KeyAgentIdentity(agent, pair.getFirst()));
            }
        } else {
            this.agent = null;
        }

        KeyPairProvider provider = session.getKeyPairProvider();
        if (provider != null) {
            for (KeyPair pair : provider.loadKeys()) {
                ids.add(new KeyPairIdentity(manager, pair));
            }
        }
        this.keys = ids.iterator();
    }

    @Override
    public boolean process(Buffer buffer) throws Exception {
        ClientSession session = getClientSession();
        String username = session.getUsername();
        String service = getService();

        // Send next key
        if (buffer == null) {
            if (keys.hasNext()) {
                current = keys.next();
                PublicKey key = current.getPublicKey();
                String algo = KeyUtils.getKeyType(key);
                String name = getName();
                if (log.isDebugEnabled()) {
                    log.debug("process({}@{})[{}] Send SSH_MSG_USERAUTH_REQUEST request {} algo={}",
                              username, session, service, name, algo);
                }

                buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST);
                buffer.putString(username);
                buffer.putString(service);
                buffer.putString(name);
                buffer.putBoolean(false);
                buffer.putString(algo);
                buffer.putPublicKey(key);
                session.writePacket(buffer);
                return true;
            }

            if (log.isDebugEnabled()) {
                log.debug("process({}@{})[{}] no more keys to send", username, session, service);
            }
            return false;
        }

        int cmd = buffer.getUByte();
        if (cmd == SshConstants.SSH_MSG_USERAUTH_PK_OK) {
            PublicKey key = current.getPublicKey();
            String algo = KeyUtils.getKeyType(key);
            String name = getName();
            if (log.isDebugEnabled()) {
                log.debug("process({}@{})[{}] Send SSH_MSG_USERAUTH_REQUEST reply {} algo={}",
                          username, session, service, name, algo);
            }

            buffer = session.prepareBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST, BufferUtils.clear(buffer));
            buffer.putString(username);
            buffer.putString(service);
            buffer.putString(name);
            buffer.putBoolean(true);
            buffer.putString(algo);
            buffer.putPublicKey(key);

            Buffer bs = new ByteArrayBuffer();
            KeyExchange kex = session.getKex();
            bs.putBytes(kex.getH());
            bs.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
            bs.putString(username);
            bs.putString(service);
            bs.putString(name);
            bs.putBoolean(true);
            bs.putString(algo);
            bs.putPublicKey(key);

            byte[] sig = current.sign(bs.getCompactData());
            bs = new ByteArrayBuffer();
            bs.putString(algo);
            bs.putBytes(sig);
            buffer.putBytes(bs.array(), bs.rpos(), bs.available());

            session.writePacket(buffer);
            return true;
        }

        throw new IllegalStateException("process(" + username + "@" + session + ")[" + service + "] received unknown packet: cmd=" + cmd);
    }

    @Override
    public void destroy() {
        if (agent != null) {
            try {
                agent.close();
            } catch (IOException e) {
                throw new RuntimeException("Failed (" + e.getClass().getSimpleName() + ") to close agent: " + e.getMessage(), e);
            }
        }
    }
}
