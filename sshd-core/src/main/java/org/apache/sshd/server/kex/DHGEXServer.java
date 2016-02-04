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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.kex.DHG;
import org.apache.sshd.common.kex.DHGroupData;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.kex.KeyExchangeFactory;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.session.ServerSession;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DHGEXServer extends AbstractDHServerKeyExchange {

    protected final DHFactory factory;
    protected DHG dh;
    protected int min;
    protected int prf;
    protected int max;
    protected byte expected;
    protected boolean oldRequest;

    protected DHGEXServer(DHFactory factory) {
        this.factory = ValidateUtils.checkNotNull(factory, "No factory");
    }

    @Override
    public final String getName() {
        return factory.getName();
    }

    public static KeyExchangeFactory newFactory(final DHFactory factory) {
        return new KeyExchangeFactory() {
            @Override
            public KeyExchange create() {
                return new DHGEXServer(factory);
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
    public void init(Session s, byte[] v_s, byte[] v_c, byte[] i_s, byte[] i_c) throws Exception {
        super.init(s, v_s, v_c, i_s, i_c);
        expected = SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST;
    }

    @Override
    public boolean next(int cmd, Buffer buffer) throws Exception {
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("next({})[{}] process command={}", this, session, KeyExchange.Utils.getGroupKexOpcodeName(cmd));
        }

        if (cmd == SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST_OLD && expected == SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST) {
            oldRequest = true;
            min = SecurityUtils.MIN_DHGEX_KEY_SIZE;
            prf = buffer.getInt();
            max = SecurityUtils.getMaxDHGroupExchangeKeySize();

            if (max < min || prf < min || max < prf) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "Protocol error: bad parameters " + min + " !< " + prf + " !< " + max);
            }
            dh = chooseDH(min, prf, max);
            f = dh.getE();
            hash = dh.getHash();
            hash.init();

            if (log.isDebugEnabled()) {
                log.debug("next({})[{}] send SSH_MSG_KEX_DH_GEX_GROUP", this, session);
            }

            buffer = session.createBuffer(SshConstants.SSH_MSG_KEX_DH_GEX_GROUP);
            buffer.putMPInt(dh.getP());
            buffer.putMPInt(dh.getG());
            session.writePacket(buffer);

            expected = SshConstants.SSH_MSG_KEX_DH_GEX_INIT;
            return false;
        }

        if (cmd == SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST && expected == SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST) {
            min = buffer.getInt();
            prf = buffer.getInt();
            max = buffer.getInt();
            if (prf < min || max < prf) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "Protocol error: bad parameters " + min + " !< " + prf + " !< " + max);
            }
            dh = chooseDH(min, prf, max);
            f = dh.getE();
            hash = dh.getHash();
            hash.init();

            if (log.isDebugEnabled()) {
                log.debug("next({})[{}] Send SSH_MSG_KEX_DH_GEX_GROUP", this, session);
            }
            buffer = session.createBuffer(SshConstants.SSH_MSG_KEX_DH_GEX_GROUP);
            buffer.putMPInt(dh.getP());
            buffer.putMPInt(dh.getG());
            session.writePacket(buffer);

            expected = SshConstants.SSH_MSG_KEX_DH_GEX_INIT;
            return false;
        }

        if (cmd != expected) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "Protocol error: expected packet " + KeyExchange.Utils.getGroupKexOpcodeName(expected)
                  + ", got " + KeyExchange.Utils.getGroupKexOpcodeName(cmd));
        }

        if (cmd == SshConstants.SSH_MSG_KEX_DH_GEX_INIT) {
            e = buffer.getMPIntAsBytes();
            dh.setF(e);
            k = dh.getK();


            byte[] k_s;
            KeyPair kp = ValidateUtils.checkNotNull(session.getHostKey(), "No server key pair available");
            String algo = session.getNegotiatedKexParameter(KexProposalOption.SERVERKEYS);
            Signature sig = ValidateUtils.checkNotNull(
                    NamedFactory.Utils.create(session.getSignatureFactories(), algo),
                    "Unknown negotiated server keys: %s",
                    algo);
            sig.initSigner(kp.getPrivate());

            buffer = new ByteArrayBuffer();
            buffer.putRawPublicKey(kp.getPublic());
            k_s = buffer.getCompactData();

            buffer.clear();
            buffer.putBytes(v_c);
            buffer.putBytes(v_s);
            buffer.putBytes(i_c);
            buffer.putBytes(i_s);
            buffer.putBytes(k_s);
            if (oldRequest) {
                buffer.putInt(prf);
            } else {
                buffer.putInt(min);
                buffer.putInt(prf);
                buffer.putInt(max);
            }
            buffer.putMPInt(dh.getP());
            buffer.putMPInt(dh.getG());
            buffer.putMPInt(e);
            buffer.putMPInt(f);
            buffer.putMPInt(k);
            hash.update(buffer.array(), 0, buffer.available());
            h = hash.digest();
            sig.update(h);

            buffer.clear();
            buffer.putString(algo);
            buffer.putBytes(sig.sign());

            byte[] sigH = buffer.getCompactData();
            if (log.isTraceEnabled()) {
                log.trace("next({})[{}][K_S]:  {}", this, session, BufferUtils.toHex(k_s));
                log.trace("next({})[{}][f]:    {}", this, session, BufferUtils.toHex(f));
                log.trace("next({})[{}][sigH]: {}", this, session, BufferUtils.toHex(sigH));
            }

            // Send response
            if (log.isDebugEnabled()) {
                log.debug("next({})[{}] Send SSH_MSG_KEX_DH_GEX_REPLY", this, session);
            }

            buffer = session.prepareBuffer(SshConstants.SSH_MSG_KEX_DH_GEX_REPLY, BufferUtils.clear(buffer));
            buffer.putBytes(k_s);
            buffer.putBytes(f);
            buffer.putBytes(sigH);
            session.writePacket(buffer);
            return true;
        }

        return false;
    }

    private DHG chooseDH(int min, int prf, int max) throws Exception {
        List<Moduli.DhGroup> groups = loadModuliGroups();

        min = Math.max(min, SecurityUtils.MIN_DHGEX_KEY_SIZE);
        prf = Math.max(prf, SecurityUtils.MIN_DHGEX_KEY_SIZE);
        prf = Math.min(prf, SecurityUtils.getMaxDHGroupExchangeKeySize());
        max = Math.min(max, SecurityUtils.getMaxDHGroupExchangeKeySize());
        int bestSize = 0;
        List<Moduli.DhGroup> selected = new ArrayList<>();
        for (Moduli.DhGroup group : groups) {
            if (group.size < min || group.size > max) {
                continue;
            }
            if ((group.size > prf && group.size < bestSize) || (group.size > bestSize && bestSize < prf)) {
                bestSize = group.size;
                selected.clear();
            }
            if (group.size == bestSize) {
                selected.add(group);
            }
        }

        ServerSession session = getServerSession();
        if (selected.isEmpty()) {
            log.warn("chooseDH({})[{}] No suitable primes found, defaulting to DHG1", this, session);
            return getDH(new BigInteger(DHGroupData.getP1()), new BigInteger(DHGroupData.getG()));
        }

        FactoryManager manager = ValidateUtils.checkNotNull(session.getFactoryManager(), "No factory manager");
        Factory<Random> factory = ValidateUtils.checkNotNull(manager.getRandomFactory(), "No random factory");
        Random random = ValidateUtils.checkNotNull(factory.create(), "No random generator");
        int which = random.random(selected.size());
        Moduli.DhGroup group = selected.get(which);
        return getDH(group.p, group.g);
    }

    protected List<Moduli.DhGroup> loadModuliGroups() throws IOException {
        ServerSession session = getServerSession();
        String moduliStr = PropertyResolverUtils.getString(session, ServerFactoryManager.MODULI_URL);

        List<Moduli.DhGroup> groups = null;
        URL moduli;
        if (!GenericUtils.isEmpty(moduliStr)) {
            try {
                moduli = new URL(moduliStr);
                groups = Moduli.parseModuli(moduli);
            } catch (IOException e) {   // OK - use internal moduli
                log.warn("Error (" + e.getClass().getSimpleName() + ") loading external moduli from " + moduliStr + ": " + e.getMessage());
            }
        }

        if (groups == null) {
            moduliStr = "/org/apache/sshd/moduli";
            try {
                moduli = getClass().getResource(moduliStr);
                if (moduli == null) {
                    throw new FileNotFoundException("Missing internal moduli file");
                }

                moduliStr = moduli.toExternalForm();
                groups = Moduli.parseModuli(moduli);
            } catch (IOException e) {
                log.warn("Error (" + e.getClass().getSimpleName() + ") loading internal moduli from " + moduliStr + ": " + e.getMessage());
                throw e;    // this time we MUST throw the exception
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Loaded moduli groups from {}", moduliStr);
        }
        return groups;
    }

    protected DHG getDH(BigInteger p, BigInteger g) throws Exception {
        return (DHG) factory.create(p, g);
    }
}
