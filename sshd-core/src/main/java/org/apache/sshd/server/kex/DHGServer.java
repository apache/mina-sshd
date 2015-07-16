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
package org.apache.sshd.server.kex;

import java.security.KeyPair;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.kex.AbstractDH;
import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.kex.KeyExchangeFactory;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DHGServer extends AbstractDHServerKeyExchange {

    protected final DHFactory factory;
    protected AbstractDH dh;

    public static KeyExchangeFactory newFactory(final DHFactory factory) {
        return new KeyExchangeFactory() {
            @Override
            public KeyExchange create() {
                return new DHGServer(factory);
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

    protected DHGServer(DHFactory factory) {
        this.factory = ValidateUtils.checkNotNull(factory, "No factory");
    }

    @Override
    public void init(AbstractSession s, byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception {
        super.init(s, V_S, V_C, I_S, I_C);
        dh = factory.create();
        hash = dh.getHash();
        hash.init();
        f = dh.getE();
    }

    @Override
    public boolean next(Buffer buffer) throws Exception {
        int cmd = buffer.getUByte();
        if (cmd != SshConstants.SSH_MSG_KEXDH_INIT) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, 
                                   "Protocol error: expected packet " + SshConstants.SSH_MSG_KEXDH_INIT + ", got " + cmd);
        }
        log.debug("Received SSH_MSG_KEXDH_INIT");
        e = buffer.getMPIntAsBytes();
        dh.setF(e);
        K = dh.getK();

        byte[] K_S;
        KeyPair kp = ValidateUtils.checkNotNull(session.getHostKey(), "No server key pair available");
        String algo = session.getNegotiatedKexParameter(KexProposalOption.SERVERKEYS);
        FactoryManager manager = session.getFactoryManager();
        Signature sig = ValidateUtils.checkNotNull(
                NamedFactory.Utils.create(manager.getSignatureFactories(), algo),
                "Unknown negotiated server keys: %s",
                algo);
        sig.initSigner(kp.getPrivate());

        buffer = new ByteArrayBuffer();
        buffer.putRawPublicKey(kp.getPublic());
        K_S = buffer.getCompactData();

        buffer.clear();
        buffer.putBytes(V_C);
        buffer.putBytes(V_S);
        buffer.putBytes(I_C);
        buffer.putBytes(I_S);
        buffer.putBytes(K_S);
        buffer.putMPInt(e);
        buffer.putMPInt(f);
        buffer.putMPInt(K);
        hash.update(buffer.array(), 0, buffer.available());
        H = hash.digest();

        byte[] sigH;
        buffer.clear();
        sig.update(H, 0, H.length);
        buffer.putString(algo);
        buffer.putBytes(sig.sign());
        sigH = buffer.getCompactData();

        if (log.isDebugEnabled()) {
            log.debug("K_S:  {}", BufferUtils.printHex(K_S));
            log.debug("f:    {}", BufferUtils.printHex(f));
            log.debug("sigH: {}", BufferUtils.printHex(sigH));
        }

        // Send response
        log.debug("Send SSH_MSG_KEXDH_REPLY");
        buffer.clear();
        buffer.rpos(5);
        buffer.wpos(5);
        buffer.putByte(SshConstants.SSH_MSG_KEXDH_REPLY);
        buffer.putBytes(K_S);
        buffer.putBytes(f);
        buffer.putBytes(sigH);
        session.writePacket(buffer);
        return true;
    }

}
