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
package org.apache.sshd.server.kex;

import java.security.KeyPair;
import java.util.Objects;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.kex.AbstractDH;
import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.kex.KeyExchangeFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.session.ServerSession;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DHGServer extends AbstractDHServerKeyExchange {

    protected final DHFactory factory;
    protected AbstractDH dh;

    protected DHGServer(DHFactory factory, Session session) {
        super(session);
        this.factory = Objects.requireNonNull(factory, "No factory");
    }

    @Override
    public final String getName() {
        return factory.getName();
    }

    public static KeyExchangeFactory newFactory(final DHFactory factory) {
        return new KeyExchangeFactory() {
            @Override
            public KeyExchange createKeyExchange(Session session) throws Exception {
                return new DHGServer(factory, session);
            }

            @Override
            public String getName() {
                return factory.getName();
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
    public void init(byte[] v_s, byte[] v_c, byte[] i_s, byte[] i_c) throws Exception {
        super.init(v_s, v_c, i_s, i_c);
        dh = factory.create();
        hash = dh.getHash();
        hash.init();
        setF(dh.getE());
    }

    @Override
    public boolean next(int cmd, Buffer buffer) throws Exception {
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("next({})[{}] process command={}",
                    this, session, KeyExchange.getSimpleKexOpcodeName(cmd));
        }

        if (cmd != SshConstants.SSH_MSG_KEXDH_INIT) {
            throw new SshException(
                    SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "Protocol error: expected packet SSH_MSG_KEXDH_INIT, got " + KeyExchange.getSimpleKexOpcodeName(cmd));
        }

        byte[] e = updateE(buffer);
        dh.setF(e);
        k = dh.getK();

        KeyPair kp = Objects.requireNonNull(session.getHostKey(), "No server key pair available");
        String algo = session.getNegotiatedKexParameter(KexProposalOption.SERVERKEYS);

        Signature sig = ValidateUtils.checkNotNull(
                NamedFactory.create(session.getSignatureFactories(), algo),
                "Unknown negotiated server keys: %s", algo);
        sig.initSigner(session, kp.getPrivate());

        buffer = new ByteArrayBuffer();
        buffer.putRawPublicKey(kp.getPublic());
        byte[] k_s = buffer.getCompactData();

        buffer.clear();
        buffer.putBytes(v_c);
        buffer.putBytes(v_s);
        buffer.putBytes(i_c);
        buffer.putBytes(i_s);
        buffer.putBytes(k_s);
        buffer.putMPInt(e);
        byte[] f = getF();
        buffer.putMPInt(f);
        buffer.putMPInt(k);

        hash.update(buffer.array(), 0, buffer.available());
        h = hash.digest();
        sig.update(session, h);

        buffer.clear();
        buffer.putString(sig.getSshAlgorithmName(algo));
        byte[] sigBytes = sig.sign(session);
        buffer.putBytes(sigBytes);

        byte[] sigH = buffer.getCompactData();
        if (log.isTraceEnabled()) {
            log.trace("next({})[{}][K_S]:  {}", this, session, BufferUtils.toHex(k_s));
            log.trace("next({})[{}][f]:    {}", this, session, BufferUtils.toHex(f));
            log.trace("next({})[{}][sigH]: {}", this, session, BufferUtils.toHex(sigH));
        }

        // Send response
        if (log.isDebugEnabled()) {
            log.debug("next({})[{}] Send SSH_MSG_KEXDH_REPLY", this, session);
        }

        buffer = session.prepareBuffer(SshConstants.SSH_MSG_KEXDH_REPLY, BufferUtils.clear(buffer));
        buffer.putBytes(k_s);
        buffer.putBytes(f);
        buffer.putBytes(sigH);
        session.writePacket(buffer);
        return true;
    }
}
