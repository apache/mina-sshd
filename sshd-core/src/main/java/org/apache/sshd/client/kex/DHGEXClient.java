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
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;


/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DHGEXClient extends AbstractDHClientKeyExchange {

    protected final DHFactory factory;
    protected byte expected;
    protected int min = SecurityUtils.MIN_DHGEX_KEY_SIZE;
    protected int prf;
    protected int max;
    protected AbstractDH dh;
    protected byte[] p;
    protected byte[] g;

    protected DHGEXClient(DHFactory factory) {
        this.factory = ValidateUtils.checkNotNull(factory, "No factory");
        this.max = SecurityUtils.getMaxDHGroupExchangeKeySize();
        this.prf = Math.min(SecurityUtils.PREFERRED_DHGEX_KEY_SIZE, max);
    }

    @Override
    public final String getName() {
        return factory.getName();
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
    public void init(Session s, byte[] v_s, byte[] v_c, byte[] i_s, byte[] i_c) throws Exception {
        super.init(s, v_s, v_c, i_s, i_c);
        if (log.isDebugEnabled()) {
            log.debug("init({}) Send SSH_MSG_KEX_DH_GEX_REQUEST", s);
        }
        Buffer buffer = s.createBuffer(SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST, Integer.SIZE);
        buffer.putInt(min);
        buffer.putInt(prf);
        buffer.putInt(max);
        s.writePacket(buffer);

        expected = SshConstants.SSH_MSG_KEX_DH_GEX_GROUP;
    }

    @Override
    public boolean next(int cmd, Buffer buffer) throws Exception {
        Session session = getSession();
        if (log.isDebugEnabled()) {
            log.debug("next({})[{}] process command={}", this, session, KeyExchange.Utils.getGroupKexOpcodeName(cmd));
        }

        if (cmd != expected) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "Protocol error: expected packet " + KeyExchange.Utils.getGroupKexOpcodeName(expected)
                  + ", got " + KeyExchange.Utils.getGroupKexOpcodeName(cmd));
        }

        if (cmd == SshConstants.SSH_MSG_KEX_DH_GEX_GROUP) {
            p = buffer.getMPIntAsBytes();
            g = buffer.getMPIntAsBytes();

            dh = getDH(new BigInteger(p), new BigInteger(g));
            hash = dh.getHash();
            hash.init();
            e = dh.getE();

            if (log.isDebugEnabled()) {
                log.debug("next({})[{}] Send SSH_MSG_KEX_DH_GEX_INIT", this, session);
            }
            buffer = session.createBuffer(SshConstants.SSH_MSG_KEX_DH_GEX_INIT, e.length + Byte.SIZE);
            buffer.putMPInt(e);
            session.writePacket(buffer);
            expected = SshConstants.SSH_MSG_KEX_DH_GEX_REPLY;
            return false;
        }

        if (cmd == SshConstants.SSH_MSG_KEX_DH_GEX_REPLY) {
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

            Signature verif = ValidateUtils.checkNotNull(
                    NamedFactory.Utils.create(session.getSignatureFactories(), keyAlg),
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

        throw new IllegalStateException("Unknown command value: " + KeyExchange.Utils.getGroupKexOpcodeName(cmd));
    }

    protected AbstractDH getDH(BigInteger p, BigInteger g) throws Exception {
        return factory.create(p, g);
    }
}
