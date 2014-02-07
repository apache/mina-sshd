/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.client.auth;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.sshd.ClientSession;
import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.session.ClientUserAuthServiceNew;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Signature;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.sshd.common.util.KeyUtils.getKeyType;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthPublicKey implements UserAuth {

    public static class Factory implements NamedFactory<UserAuth> {
        public String getName() {
            return "publickey";
        }
        public UserAuth create() {
            return new UserAuthPublicKey();
        }
    }

    protected final Logger log = LoggerFactory.getLogger(getClass());
    private ClientSession session;
    private String service;
    private SshAgent agent;
    private Iterator<PublicKeyIdentity> keys;
    private PublicKeyIdentity current;

    public void init(ClientSession session, String service, List<Object> identities) throws Exception {
        this.session = session;
        this.service = service;
        List<PublicKeyIdentity> ids = new ArrayList<PublicKeyIdentity>();
        for (Object o : identities) {
            if (o instanceof KeyPair) {
                ids.add(new KeyPairIdentity(session.getFactoryManager(), (KeyPair) o));
            }
        }
        SshAgentFactory factory = session.getFactoryManager().getAgentFactory();
        if (factory != null) {
            this.agent = factory.createClient(session.getFactoryManager());
            for (SshAgent.Pair<PublicKey, String> pair : agent.getIdentities()) {
                ids.add(new KeyAgentIdentity(agent, pair.getFirst()));
            }
        } else {
            this.agent = null;
        }
        KeyPairProvider provider = session.getFactoryManager().getKeyPairProvider();
        if (provider != null) {
            for (KeyPair pair : provider.loadKeys()) {
                ids.add(new KeyPairIdentity(session.getFactoryManager(), pair));
            }
        }
        this.keys = ids.iterator();
    }

    public boolean process(Buffer buffer) throws Exception {
        // Send next key
        if (buffer == null) {
            if (keys.hasNext()) {
                current = keys.next();
                PublicKey key = current.getPublicKey();
                String algo = getKeyType(key);
                log.debug("Send SSH_MSG_USERAUTH_REQUEST for publickey");
                buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST);
                buffer.putString(session.getUsername());
                buffer.putString(service);
                buffer.putString("publickey");
                buffer.putByte((byte) 0);
                buffer.putString(algo);
                buffer.putPublicKey(key);
                session.writePacket(buffer);
                return true;
            }
            return false;
        }
        byte cmd = buffer.getByte();
        if (cmd == SshConstants.SSH_MSG_USERAUTH_PK_OK) {
            PublicKey key = current.getPublicKey();
            String algo = getKeyType(key);
            log.debug("Send SSH_MSG_USERAUTH_REQUEST for publickey");
            buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST);
            buffer.putString(session.getUsername());
            buffer.putString(service);
            buffer.putString("publickey");
            buffer.putByte((byte) 1);
            buffer.putString(algo);
            buffer.putPublicKey(key);

            Buffer bs = new Buffer();
            bs.putString(((AbstractSession) session).getKex().getH());
            bs.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
            bs.putString(session.getUsername());
            bs.putString(service);
            bs.putString("publickey");
            bs.putByte((byte) 1);
            bs.putString(algo);
            bs.putPublicKey(key);
            byte[] sig = current.sign(bs.getCompactData());

            bs = new Buffer();
            bs.putString(algo);
            bs.putBytes(sig);
            buffer.putBytes(bs.array(), bs.rpos(), bs.available());

            session.writePacket(buffer);
            return true;
        }

        throw new IllegalStateException("Received unknown packet");
    }

    public void destroy() {
        if (agent != null) {
            agent.close();
        }
    }

    interface PublicKeyIdentity {
        PublicKey getPublicKey();
        byte[] sign(byte[] data) throws Exception;
    }

    static class KeyAgentIdentity implements PublicKeyIdentity {
        private final SshAgent agent;
        private final PublicKey key;

        KeyAgentIdentity(SshAgent agent, PublicKey key) {
            this.agent = agent;
            this.key = key;
        }

        public PublicKey getPublicKey() {
            return key;
        }

        public byte[] sign(byte[] data) throws Exception {
            return agent.sign(key, data);
        }
    }

    static class KeyPairIdentity implements PublicKeyIdentity {
        private final KeyPair pair;
        private final FactoryManager manager;

        KeyPairIdentity(FactoryManager manager, KeyPair pair) {
            this.manager = manager;
            this.pair = pair;
        }

        public PublicKey getPublicKey() {
            return pair.getPublic();
        }

        public byte[] sign(byte[] data) throws Exception {
            Signature verif = NamedFactory.Utils.create(manager.getSignatureFactories(), getKeyType(pair));
            verif.init(pair.getPublic(), pair.getPrivate());
            verif.update(data, 0, data.length);
            return verif.sign();
        }
    }

}
