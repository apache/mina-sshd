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
import java.security.PublicKey;
import java.util.Objects;

import org.apache.sshd.client.session.AbstractClientSession;
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
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DHGEXClient extends AbstractDHClientKeyExchange {

    protected final DHFactory factory;
    protected byte expected;
    protected int min;
    protected int prf;
    protected int max;
    protected AbstractDH dh;
    protected byte[] g;

    private byte[] p;
    private BigInteger pValue;

    protected DHGEXClient(DHFactory factory, Session session) {
        super(session);
        this.factory = Objects.requireNonNull(factory, "No factory");

        // SSHD-941 give the user a chance to intervene in the choice
        min = CoreModuleProperties.PROP_DHGEX_CLIENT_MIN_KEY.get(session)
                .orElse(SecurityUtils.getMinDHGroupExchangeKeySize());
        max = CoreModuleProperties.PROP_DHGEX_CLIENT_MAX_KEY.get(session)
                .orElse(SecurityUtils.getMaxDHGroupExchangeKeySize());
        prf = CoreModuleProperties.PROP_DHGEX_CLIENT_PRF_KEY.get(session)
                .orElse(Math.min(SecurityUtils.PREFERRED_DHGEX_KEY_SIZE, max));
    }

    @Override
    public final String getName() {
        return factory.getName();
    }

    protected byte[] getP() {
        return p;
    }

    protected BigInteger getPValue() {
        if (pValue == null) {
            pValue = BufferUtils.fromMPIntBytes(getP());
        }

        return pValue;
    }

    protected void setP(byte[] p) {
        this.p = p;

        if (pValue != null) {
            pValue = null;  // force lazy re-initialization
        }
    }

    protected void validateEValue() throws Exception {
        validateEValue(getPValue());
    }

    protected void validateFValue() throws Exception {
        validateFValue(getPValue());
    }

    public static KeyExchangeFactory newFactory(DHFactory delegate) {
        return new KeyExchangeFactory() {
            @Override
            public String getName() {
                return delegate.getName();
            }

            @Override
            public KeyExchange createKeyExchange(Session session) throws Exception {
                return new DHGEXClient(delegate, session);
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

        Session s = getSession();
        if (log.isDebugEnabled()) {
            log.debug("init({})[{}] Send SSH_MSG_KEX_DH_GEX_REQUEST - min={}, prf={}, max={}",
                    this, s, min, prf, max);
        }
        if ((max < min) || (prf < min) || (max < prf)) {
            throw new SshException(
                    SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "Protocol error: bad parameters " + min + " !< " + prf + " !< " + max);
        }

        Buffer buffer = s.createBuffer(SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST, Integer.SIZE);
        buffer.putInt(min);
        buffer.putInt(prf);
        buffer.putInt(max);
        s.writePacket(buffer);

        expected = SshConstants.SSH_MSG_KEX_DH_GEX_GROUP;
    }

    @Override
    @SuppressWarnings("checkstyle:VariableDeclarationUsageDistance")
    public boolean next(int cmd, Buffer buffer) throws Exception {
        AbstractClientSession session = getClientSession();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("next({})[{}] process command={} (expected={})",
                    this, session, KeyExchange.getGroupKexOpcodeName(cmd),
                    KeyExchange.getGroupKexOpcodeName(expected));
        }

        if (cmd != expected) {
            throw new SshException(
                    SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "Protocol error: expected packet " + KeyExchange.getGroupKexOpcodeName(expected)
                                                                      + ", got " + KeyExchange.getGroupKexOpcodeName(cmd));
        }

        if (cmd == SshConstants.SSH_MSG_KEX_DH_GEX_GROUP) {
            setP(buffer.getMPIntAsBytes());
            g = buffer.getMPIntAsBytes();

            dh = getDH(getPValue(), new BigInteger(g));
            hash = dh.getHash();
            hash.init();

            byte[] e = updateE(dh.getE());
            validateEValue();

            if (debugEnabled) {
                log.debug("next({})[{}] Send SSH_MSG_KEX_DH_GEX_INIT", this, session);
            }

            buffer = session.createBuffer(
                    SshConstants.SSH_MSG_KEX_DH_GEX_INIT, e.length + Byte.SIZE);
            buffer.putMPInt(e);
            session.writePacket(buffer);
            expected = SshConstants.SSH_MSG_KEX_DH_GEX_REPLY;
            return false;
        }

        if (cmd == SshConstants.SSH_MSG_KEX_DH_GEX_REPLY) {
            if (debugEnabled) {
                log.debug("next({})[{}] validate SSH_MSG_KEX_DH_GEX_REPLY - min={}, prf={}, max={}",
                        this, session, min, prf, max);
            }

            byte[] k_s = buffer.getBytes();
            byte[] f = updateF(buffer);
            byte[] sig = buffer.getBytes();

            validateFValue();

            dh.setF(f);
            k = dh.getK();

            buffer = new ByteArrayBuffer(k_s);
            PublicKey serverKey = buffer.getRawPublicKey();

            String keyAlg = KeyUtils.getKeyType(serverKey);
            if (GenericUtils.isEmpty(keyAlg)) {
                throw new SshException(
                        "Unsupported server key type: " + serverKey.getAlgorithm()
                                       + " [" + serverKey.getFormat() + "]");
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
            buffer.putMPInt(getP());
            buffer.putMPInt(g);
            buffer.putMPInt(getE());
            buffer.putMPInt(f);
            buffer.putMPInt(k);
            hash.update(buffer.array(), 0, buffer.available());
            h = hash.digest();

            Signature verif = ValidateUtils.checkNotNull(
                    NamedFactory.create(session.getSignatureFactories(), keyAlg),
                    "No verifier located for algorithm=%s", keyAlg);
            verif.initVerifier(session, serverKey);
            verif.update(session, h);
            if (!verif.verify(session, sig)) {
                throw new SshException(
                        SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "KeyExchange signature verification failed for key type=" + keyAlg);
            }
            session.setServerKey(serverKey);
            return true;
        }

        throw new IllegalStateException("Unknown command value: " + KeyExchange.getGroupKexOpcodeName(cmd));
    }

    protected AbstractDH getDH(BigInteger p, BigInteger g) throws Exception {
        return factory.create(p, g);
    }
}
