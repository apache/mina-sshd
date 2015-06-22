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
package org.apache.sshd.client.kex;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.kex.AbstractDH;
import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.session.AbstractSession;
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

    public static final NamedFactory<KeyExchange> newFactory(final DHFactory delegate) {
        return new NamedFactory<KeyExchange>() {
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

    protected DHGClient(DHFactory factory) {
        this.factory = ValidateUtils.checkNotNull(factory, "No factory", GenericUtils.EMPTY_OBJECT_ARRAY);
    }

    @Override
    public void init(AbstractSession s, byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception {
        super.init(s, V_S, V_C, I_S, I_C);
        dh = getDH();
        hash =  dh.getHash();
        hash.init();
        e = dh.getE();

        log.debug("Send SSH_MSG_KEXDH_INIT");
        Buffer buffer = s.createBuffer(SshConstants.SSH_MSG_KEXDH_INIT);
        buffer.putMPInt(e);
        session.writePacket(buffer);
    }

    protected AbstractDH getDH() throws Exception {
        return factory.create();
    }

    @Override
    public boolean next(Buffer buffer) throws Exception {
        byte cmd = buffer.getByte();
        if (cmd != SshConstants.SSH_MSG_KEXDH_REPLY) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                                   "Protocol error: expected packet SSH_MSG_KEXDH_REPLY, got " + cmd);
        }

        log.debug("Received SSH_MSG_KEXDH_REPLY");
        
        byte[] K_S = buffer.getBytes();
        f = buffer.getMPIntAsBytes();
        byte[] sig = buffer.getBytes();
        dh.setF(f);
        K = dh.getK();

        buffer = new ByteArrayBuffer(K_S);
        serverKey = buffer.getRawPublicKey();
        final String keyAlg = KeyUtils.getKeyType(serverKey);
        if (GenericUtils.isEmpty(keyAlg)) {
            throw new SshException("Unsupported server key type");
        }

        buffer = new ByteArrayBuffer();
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

        FactoryManager manager = session.getFactoryManager();
        Signature verif = ValidateUtils.checkNotNull(NamedFactory.Utils.create(manager.getSignatureFactories(), keyAlg),
                            "No verifier located for algorithm=%s",
                            keyAlg);
        verif.initVerifier(serverKey);
        verif.update(H);
        if (!verif.verify(sig)) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, "KeyExchange signature verification failed");
        }
        return true;
    }

}
