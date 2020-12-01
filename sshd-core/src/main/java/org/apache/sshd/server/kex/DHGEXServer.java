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
import java.util.Objects;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
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
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.core.CoreModuleProperties;
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

    protected DHGEXServer(DHFactory factory, Session session) {
        super(session);
        this.factory = Objects.requireNonNull(factory, "No factory");
    }

    @Override
    public final String getName() {
        return factory.getName();
    }

    public static KeyExchangeFactory newFactory(DHFactory factory) {
        return new KeyExchangeFactory() {
            @Override
            public KeyExchange createKeyExchange(Session session) throws Exception {
                return new DHGEXServer(factory, session);
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
        expected = SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST;
    }

    @Override
    public boolean next(int cmd, Buffer buffer) throws Exception {
        ServerSession session = getServerSession();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("next({})[{}] process command={} (expected={})",
                    this, session, KeyExchange.getGroupKexOpcodeName(cmd),
                    KeyExchange.getGroupKexOpcodeName(expected));
        }

        if ((cmd == SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST_OLD)
                && (expected == SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST)) {
            oldRequest = true;
            min = CoreModuleProperties.PROP_DHGEX_SERVER_MIN_KEY.get(session)
                    .orElse(SecurityUtils.getMinDHGroupExchangeKeySize());
            prf = buffer.getInt();
            max = CoreModuleProperties.PROP_DHGEX_SERVER_MAX_KEY.get(session)
                    .orElse(SecurityUtils.getMaxDHGroupExchangeKeySize());

            if ((max < min) || (prf < min) || (max < prf)) {
                throw new SshException(
                        SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "Protocol error: bad parameters " + min + " !< " + prf + " !< " + max);
            }

            dh = chooseDH(min, prf, max);

            setF(dh.getE());

            BigInteger pValue = dh.getP();
            validateFValue(pValue);

            hash = dh.getHash();
            hash.init();

            if (debugEnabled) {
                log.debug("next({})[{}] send (old request) SSH_MSG_KEX_DH_GEX_GROUP - min={}, prf={}, max={}",
                        this, session, min, prf, max);
            }

            buffer = session.createBuffer(SshConstants.SSH_MSG_KEX_DH_GEX_GROUP);
            buffer.putMPInt(pValue);
            buffer.putMPInt(dh.getG());
            session.writePacket(buffer);

            expected = SshConstants.SSH_MSG_KEX_DH_GEX_INIT;
            return false;
        }

        if ((cmd == SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST)
                && (expected == SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST)) {
            min = buffer.getInt();
            prf = buffer.getInt();
            max = buffer.getInt();

            if ((prf < min) || (max < prf)) {
                throw new SshException(
                        SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "Protocol error: bad parameters " + min + " !< " + prf + " !< " + max);
            }

            dh = chooseDH(min, prf, max);

            setF(dh.getE());

            BigInteger pValue = dh.getP();
            validateFValue(pValue);

            hash = dh.getHash();
            hash.init();

            if (debugEnabled) {
                log.debug("next({})[{}] Send SSH_MSG_KEX_DH_GEX_GROUP - min={}, prf={}, max={}",
                        this, session, min, prf, max);
            }
            buffer = session.createBuffer(SshConstants.SSH_MSG_KEX_DH_GEX_GROUP);
            buffer.putMPInt(pValue);
            buffer.putMPInt(dh.getG());
            session.writePacket(buffer);

            expected = SshConstants.SSH_MSG_KEX_DH_GEX_INIT;
            return false;
        }

        if (cmd != expected) {
            throw new SshException(
                    SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "Protocol error: expected packet " + KeyExchange.getGroupKexOpcodeName(expected)
                                                                      + ", got " + KeyExchange.getGroupKexOpcodeName(cmd));
        }

        if (cmd == SshConstants.SSH_MSG_KEX_DH_GEX_INIT) {
            byte[] e = updateE(buffer.getMPIntAsBytes());
            BigInteger pValue = dh.getP();
            validateEValue(pValue);

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

            if (oldRequest) {
                buffer.putInt(prf);
            } else {
                buffer.putInt(min);
                buffer.putInt(prf);
                buffer.putInt(max);
            }

            buffer.putMPInt(pValue);
            buffer.putMPInt(dh.getG());
            buffer.putMPInt(e);
            byte[] f = getF();
            buffer.putMPInt(f);
            buffer.putMPInt(k);

            hash.update(buffer.array(), 0, buffer.available());
            h = hash.digest();
            sig.update(session, h);

            buffer.clear();
            buffer.putString(algo);
            byte[] sigBytes = sig.sign(session);
            buffer.putBytes(sigBytes);

            byte[] sigH = buffer.getCompactData();
            if (log.isTraceEnabled()) {
                log.trace("next({})[{}][K_S]:  {}", this, session, BufferUtils.toHex(k_s));
                log.trace("next({})[{}][f]:    {}", this, session, BufferUtils.toHex(f));
                log.trace("next({})[{}][sigH]: {}", this, session, BufferUtils.toHex(sigH));
            }

            // Send response
            if (debugEnabled) {
                log.debug("next({})[{}] Send SSH_MSG_KEX_DH_GEX_REPLY - old={}, min={}, prf={}, max={}",
                        this, session, oldRequest, min, prf, max);
            }

            buffer = session.prepareBuffer(
                    SshConstants.SSH_MSG_KEX_DH_GEX_REPLY, BufferUtils.clear(buffer));
            buffer.putBytes(k_s);
            buffer.putBytes(f);
            buffer.putBytes(sigH);
            session.writePacket(buffer);
            return true;
        }

        return false;
    }

    protected DHG chooseDH(int min, int prf, int max) throws Exception {
        ServerSession session = getServerSession();
        List<Moduli.DhGroup> groups = loadModuliGroups(session);
        List<Moduli.DhGroup> selected = selectModuliGroups(session, min, prf, max, groups);
        if (GenericUtils.isEmpty(selected)) {
            log.warn("chooseDH({})[{}][prf={}, min={}, max={}] No suitable primes found, defaulting to DHG1",
                    this, session, prf, min, max);
            return getDH(new BigInteger(DHGroupData.getP1()), new BigInteger(DHGroupData.getG()));
        }

        FactoryManager manager = Objects.requireNonNull(session.getFactoryManager(), "No factory manager");
        Factory<Random> factory = Objects.requireNonNull(manager.getRandomFactory(), "No random factory");
        Random random = Objects.requireNonNull(factory.create(), "No random generator");
        int which = random.random(selected.size());
        Moduli.DhGroup group = selected.get(which);
        if (log.isTraceEnabled()) {
            log.trace("chooseDH({})[{}][prf={}, min={}, max={}] selected {}",
                    this, session, prf, min, max, group);
        }

        return getDH(group.getP(), group.getG());
    }

    protected List<Moduli.DhGroup> selectModuliGroups(
            ServerSession session, int min, int prf, int max, List<Moduli.DhGroup> groups)
            throws Exception {
        int maxDHGroupExchangeKeySize = SecurityUtils.getMaxDHGroupExchangeKeySize();
        int minDHGroupExchangeKeySize = SecurityUtils.getMinDHGroupExchangeKeySize();
        min = Math.max(min, minDHGroupExchangeKeySize);
        prf = Math.max(prf, minDHGroupExchangeKeySize);
        prf = Math.min(prf, maxDHGroupExchangeKeySize);
        max = Math.min(max, maxDHGroupExchangeKeySize);

        List<Moduli.DhGroup> selected = new ArrayList<>();
        int bestSize = 0;
        boolean traceEnabled = log.isTraceEnabled();
        for (Moduli.DhGroup group : groups) {
            int size = group.getSize();
            if ((size < min) || (size > max)) {
                if (traceEnabled) {
                    log.trace("selectModuliGroups({})[{}] - skip group={} - size not in range [{}-{}]",
                            this, session, group, min, max);
                }
                continue;
            }

            if (((size > prf) && (size < bestSize)) || ((size > bestSize) && (bestSize < prf))) {
                bestSize = size;
                if (traceEnabled) {
                    log.trace("selectModuliGroups({})[{}][prf={}, min={}, max={}] new best size={} from group={}",
                            this, session, prf, min, max, bestSize, group);
                }
                selected.clear();
            }

            if (size == bestSize) {
                if (traceEnabled) {
                    log.trace("selectModuliGroups({})[{}][prf={}, min={}, max={}] selected {}",
                            this, session, prf, min, max, group);
                }
                selected.add(group);
            }
        }

        return selected;
    }

    protected List<Moduli.DhGroup> loadModuliGroups(ServerSession session) throws IOException {
        String moduliStr = CoreModuleProperties.MODULI_URL.getOrNull(session);
        List<Moduli.DhGroup> groups = null;
        if (!GenericUtils.isEmpty(moduliStr)) {
            try {
                URL moduli = new URL(moduliStr);
                groups = Moduli.parseModuli(moduli);
            } catch (IOException e) { // OK - use internal moduli
                log.warn("loadModuliGroups({})[{}] Error ({}) loading external moduli from {}: {}",
                        this, session, e.getClass().getSimpleName(), moduliStr, e.getMessage());
            }
        }

        if (groups == null) {
            moduliStr = Moduli.INTERNAL_MODULI_RESPATH;
            try {
                URL moduli = getClass().getResource(moduliStr);
                if (moduli == null) {
                    throw new FileNotFoundException("Missing internal moduli file");
                }

                moduliStr = moduli.toExternalForm();
                groups = Moduli.loadInternalModuli(moduli);
            } catch (IOException e) {
                log.warn("loadModuliGroups({})[{}] Error ({}) loading internal moduli from {}: {}",
                        this, session, e.getClass().getSimpleName(), moduliStr, e.getMessage());
                throw e; // this time we MUST throw the exception
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("loadModuliGroups({})[{}] Loaded {} moduli groups from {}",
                    this, session, GenericUtils.size(groups), moduliStr);
        }
        return groups;
    }

    protected DHG getDH(BigInteger p, BigInteger g) throws Exception {
        return (DHG) factory.create(p, g);
    }
}
