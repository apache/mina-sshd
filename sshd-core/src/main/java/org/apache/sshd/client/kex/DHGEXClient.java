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

import java.math.BigInteger;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.kex.AbstractDH;
import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;


/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DHGEXClient extends AbstractDHClientKeyExchange {

    protected final DHFactory factory;
    protected byte expected;
    protected int min = 1024;
    protected int prf = 4096;
    protected int max = 8192;
    protected AbstractDH dh;
    protected byte[] p;
    protected byte[] g;

    public static final NamedFactory<KeyExchange> newFactory(final DHFactory delegate) {
        return new NamedFactory<KeyExchange>() {
            @Override
            public String getName() {
                return delegate.getName();
            }

            @Override
            public KeyExchange create() {
                return new DHGEXClient(delegate);
            }

            @Override
            public String toString() {
                return NamedFactory.class.getSimpleName()
                        + "<" + KeyExchange.class.getSimpleName() + ">"
                        + "[" + getName() + "]";
            }
        };
    }
    protected DHGEXClient(DHFactory factory) {
        super();
        this.factory = factory;
    }

    @Override
    public void init(AbstractSession s, byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception {
        super.init(s, V_S, V_C, I_S, I_C);
        log.debug("Send SSH_MSG_KEX_DH_GEX_REQUEST");
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST);
        buffer.putInt(min);
        buffer.putInt(prf);
        buffer.putInt(max);
        session.writePacket(buffer);

        expected = SshConstants.SSH_MSG_KEX_DH_GEX_GROUP;
    }

    @Override
    public boolean next(Buffer buffer) throws Exception {
        byte cmd = buffer.getByte();
        if (cmd != expected) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "Protocol error: expected packet " + expected + ", got " + cmd);
        }

        if (cmd == SshConstants.SSH_MSG_KEX_DH_GEX_GROUP) {
            log.debug("Received SSH_MSG_KEX_DH_GEX_GROUP");
            p = buffer.getMPIntAsBytes();
            g = buffer.getMPIntAsBytes();

            dh = getDH(new BigInteger(p), new BigInteger(g));
            hash = dh.getHash();
            hash.init();
            e = dh.getE();

            log.debug("Send SSH_MSG_KEX_DH_GEX_INIT");
            buffer = session.createBuffer(SshConstants.SSH_MSG_KEX_DH_GEX_INIT);
            buffer.putMPInt(e);
            session.writePacket(buffer);
            expected = SshConstants.SSH_MSG_KEX_DH_GEX_REPLY;
            return false;
        }

        if (cmd == SshConstants.SSH_MSG_KEX_DH_GEX_REPLY) {
            log.debug("Received SSH_MSG_KEX_DH_GEX_REPLY");
            byte[] K_S = buffer.getBytes();
            f = buffer.getMPIntAsBytes();
            byte[] sig = buffer.getBytes();
            dh.setF(f);
            K = dh.getK();

            buffer = new ByteArrayBuffer(K_S);
            serverKey = buffer.getRawPublicKey();
            final String keyAlg = KeyUtils.getKeyType(serverKey);
            if (keyAlg == null) {
                throw new SshException("Unsupported server key type");
            }

            buffer = new ByteArrayBuffer();
            buffer.putBytes(V_C);
            buffer.putBytes(V_S);
            buffer.putBytes(I_C);
            buffer.putBytes(I_S);
            buffer.putBytes(K_S);
            buffer.putInt(min);
            buffer.putInt(prf);
            buffer.putInt(max);
            buffer.putMPInt(p);
            buffer.putMPInt(g);
            buffer.putMPInt(e);
            buffer.putMPInt(f);
            buffer.putMPInt(K);
            hash.update(buffer.array(), 0, buffer.available());
            H = hash.digest();

            Signature verif = NamedFactory.Utils.create(session.getFactoryManager().getSignatureFactories(), keyAlg);
            verif.init(serverKey, null);
            verif.update(H, 0, H.length);
            if (!verif.verify(sig)) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "KeyExchange signature verification failed");
            }
            return true;
        }

        throw new IllegalStateException("Unknown command value: " + cmd);
    }

    protected AbstractDH getDH(BigInteger p, BigInteger g) throws Exception {
        return factory.create(p, g);
    }

}
