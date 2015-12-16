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
package org.apache.sshd.client.kex;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.kex.AbstractDH;
import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.kex.KeyExchangeFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * Base class for DHG key exchange algorithms.
 * Implementations will only have to configure the required data on the
 * {@link org.apache.sshd.common.kex.DHG} class in the {@link #getDH()} method.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DHGClient extends AbstractDHClientKeyExchange {

    protected final DHFactory factory;
    protected AbstractDH dh;

    protected DHGClient(DHFactory factory) {
        this.factory = ValidateUtils.checkNotNull(factory, "No factory");
    }

    @Override
    public final String getName() {
        return factory.getName();
    }

    public static final KeyExchangeFactory newFactory(final DHFactory delegate) {
        return new KeyExchangeFactory() {
            @Override
            public String getName() {
                return delegate.getName();
            }

            @Override
            public KeyExchange create() {
                return new DHGClient(delegate);
            }

            @Override
            public String toString() {
                return NamedFactory.class.getSimpleName()
                        + "<" + KeyExchange.class.getSimpleName() + ">"
                        + "[" + getName() + "]";
            }
        };
    }

    @Override
    public void init(Session s, byte[] v_s, byte[] v_c, byte[] i_s, byte[] i_c) throws Exception {
        super.init(s, v_s, v_c, i_s, i_c);
        dh = getDH();
        hash = dh.getHash();
        hash.init();
        e = dh.getE();

        if (log.isDebugEnabled()) {
            log.debug("init({})[{}] Send SSH_MSG_KEXDH_INIT", this, s);
        }
        Buffer buffer = s.createBuffer(SshConstants.SSH_MSG_KEXDH_INIT, e.length + Integer.SIZE);
        buffer.putMPInt(e);

        s.writePacket(buffer);
    }

    protected AbstractDH getDH() throws Exception {
        return factory.create();
    }

    @Override
    public boolean next(int cmd, Buffer buffer) throws Exception {
        Session session = getSession();
        if (log.isDebugEnabled()) {
            log.debug("next({})[{}] process command={}", this, session, KeyExchange.Utils.getSimpleKexOpcodeName(cmd));
        }
        if (cmd != SshConstants.SSH_MSG_KEXDH_REPLY) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "Protocol error: expected packet SSH_MSG_KEXDH_REPLY, got " + KeyExchange.Utils.getSimpleKexOpcodeName(cmd));
        }

        byte[] k_s = buffer.getBytes();
        f = buffer.getMPIntAsBytes();
        byte[] sig = buffer.getBytes();
        dh.setF(f);
        k = dh.getK();

        buffer = new ByteArrayBuffer(k_s);
        serverKey = buffer.getRawPublicKey();
        final String keyAlg = KeyUtils.getKeyType(serverKey);
        if (GenericUtils.isEmpty(keyAlg)) {
            throw new SshException("Unsupported server key type");
        }

        buffer = new ByteArrayBuffer();
        buffer.putBytes(v_c);
        buffer.putBytes(v_s);
        buffer.putBytes(i_c);
        buffer.putBytes(i_s);
        buffer.putBytes(k_s);
        buffer.putMPInt(e);
        buffer.putMPInt(f);
        buffer.putMPInt(k);
        hash.update(buffer.array(), 0, buffer.available());
        h = hash.digest();

        Signature verif = ValidateUtils.checkNotNull(NamedFactory.Utils.create(session.getSignatureFactories(), keyAlg),
                "No verifier located for algorithm=%s",
                keyAlg);
        verif.initVerifier(serverKey);
        verif.update(h);
        if (!verif.verify(sig)) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, "KeyExchange signature verification failed for key type=" + keyAlg);
        }
        return true;
    }
}
