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

import java.math.BigInteger;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.kex.AbstractDH;
import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.kex.KeyExchangeFactory;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;


/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DHGEXClient extends AbstractDHClientKeyExchange {

    protected final DHFactory factory;
    protected byte expected;
    protected int min = 1024;
    protected int prf;
    protected int max;
    protected AbstractDH dh;
    protected byte[] p;
    protected byte[] g;

    protected DHGEXClient(DHFactory factory) {
        this.factory = ValidateUtils.checkNotNull(factory, "No factory");
        max = SecurityUtils.getMaxDHGroupExchangeKeySize();
        prf = Math.min(4096, max);
    }

    public static KeyExchangeFactory newFactory(final DHFactory delegate) {
        return new KeyExchangeFactory() {
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

    @Override
    public void init(AbstractSession s, byte[] v_s, byte[] v_c, byte[] i_s, byte[] i_c) throws Exception {
        super.init(s, v_s, v_c, i_s, i_c);
        log.debug("Send SSH_MSG_KEX_DH_GEX_REQUEST");
        Buffer buffer = s.createBuffer(SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST);
        buffer.putInt(min);
        buffer.putInt(prf);
        buffer.putInt(max);
        s.writePacket(buffer);

        expected = SshConstants.SSH_MSG_KEX_DH_GEX_GROUP;
    }

    @Override
    public boolean next(Buffer buffer) throws Exception {
        int cmd = buffer.getUByte();
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
            Session session = getSession();
            buffer = session.prepareBuffer(SshConstants.SSH_MSG_KEX_DH_GEX_INIT, BufferUtils.clear(buffer));
            buffer.putMPInt(e);
            session.writePacket(buffer);
            expected = SshConstants.SSH_MSG_KEX_DH_GEX_REPLY;
            return false;
        }

        if (cmd == SshConstants.SSH_MSG_KEX_DH_GEX_REPLY) {
            log.debug("Received SSH_MSG_KEX_DH_GEX_REPLY");
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
            buffer.putInt(min);
            buffer.putInt(prf);
            buffer.putInt(max);
            buffer.putMPInt(p);
            buffer.putMPInt(g);
            buffer.putMPInt(e);
            buffer.putMPInt(f);
            buffer.putMPInt(k);
            hash.update(buffer.array(), 0, buffer.available());
            h = hash.digest();

            Session session = getSession();
            FactoryManager manager = session.getFactoryManager();
            Signature verif = ValidateUtils.checkNotNull(
                    NamedFactory.Utils.create(manager.getSignatureFactories(), keyAlg),
                    "No verifier located for algorithm=%s",
                    keyAlg);
            verif.initVerifier(serverKey);
            verif.update(h);
            if (!verif.verify(sig)) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "KeyExchange signature verification failed for key type=" + keyAlg);
            }
            return true;
        }

        throw new IllegalStateException("Unknown command value: " + cmd);
    }

    protected AbstractDH getDH(BigInteger p, BigInteger g) throws Exception {
        return factory.create(p, g);
    }

}
