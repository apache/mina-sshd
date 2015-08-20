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

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerUtils;
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
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.ServerFactoryManager;

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
    public void init(AbstractSession s, byte[] v_s, byte[] v_c, byte[] i_s, byte[] i_c) throws Exception {
        super.init(s, v_s, v_c, i_s, i_c);
        expected = SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST;
    }

    @Override
    public boolean next(Buffer buffer) throws Exception {
        int cmd = buffer.getUByte();

        if (cmd == SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST_OLD && expected == SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST) {
            log.debug("Received SSH_MSG_KEX_DH_GEX_REQUEST_OLD");
            oldRequest = true;
            min = 1024;
            prf = buffer.getInt();
            max = 8192;

            if (max < min || prf < min || max < prf) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "Protocol error: bad parameters " + min + " !< " + prf + " !< " + max);
            }
            dh = chooseDH(min, prf, max);
            f = dh.getE();
            hash = dh.getHash();
            hash.init();

            log.debug("Send SSH_MSG_KEX_DH_GEX_GROUP");
            buffer = session.createBuffer(SshConstants.SSH_MSG_KEX_DH_GEX_GROUP);
            buffer.putMPInt(dh.getP());
            buffer.putMPInt(dh.getG());
            session.writePacket(buffer);

            expected = SshConstants.SSH_MSG_KEX_DH_GEX_INIT;
            return false;
        }
        if (cmd == SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST && expected == SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST) {
            log.debug("Received SSH_MSG_KEX_DH_GEX_REQUEST");
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

            log.debug("Send SSH_MSG_KEX_DH_GEX_GROUP");
            buffer = session.createBuffer(SshConstants.SSH_MSG_KEX_DH_GEX_GROUP);
            buffer.putMPInt(dh.getP());
            buffer.putMPInt(dh.getG());
            session.writePacket(buffer);

            expected = SshConstants.SSH_MSG_KEX_DH_GEX_INIT;
            return false;
        }
        if (cmd != expected) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "Protocol error: expected packet " + expected + ", got " + cmd);
        }

        if (cmd == SshConstants.SSH_MSG_KEX_DH_GEX_INIT) {
            log.debug("Received SSH_MSG_KEX_DH_GEX_INIT");
            e = buffer.getMPIntAsBytes();
            dh.setF(e);
            k = dh.getK();


            byte[] k_s;
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

            byte[] sigH;
            buffer.clear();
            sig.update(h, 0, h.length);
            buffer.putString(algo);
            buffer.putBytes(sig.sign());
            sigH = buffer.getCompactData();

            if (log.isDebugEnabled()) {
                log.debug("K_S:  {}", BufferUtils.printHex(k_s));
                log.debug("f:    {}", BufferUtils.printHex(f));
                log.debug("sigH: {}", BufferUtils.printHex(sigH));
            }

            // Send response
            log.debug("Send SSH_MSG_KEX_DH_GEX_REPLY");
            buffer.clear();
            buffer.rpos(5);
            buffer.wpos(5);
            buffer.putByte(SshConstants.SSH_MSG_KEX_DH_GEX_REPLY);
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

        min = Math.max(min, 1024);
        prf = Math.max(prf, 1024);
        // Keys of size > 1024 are not support by default with JCE, so only enable
        // those if BouncyCastle is registered
        prf = Math.min(prf, SecurityUtils.isBouncyCastleRegistered() ? 8192 : 1024);
        max = Math.min(max, 8192);
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
        if (selected.isEmpty()) {
            log.warn("No suitable primes found, defaulting to DHG1");
            return getDH(new BigInteger(DHGroupData.getP1()), new BigInteger(DHGroupData.getG()));
        }
        Random random = session.getFactoryManager().getRandomFactory().create();
        int which = random.random(selected.size());
        Moduli.DhGroup group = selected.get(which);
        return getDH(group.p, group.g);
    }

    protected List<Moduli.DhGroup> loadModuliGroups() throws IOException {
        List<Moduli.DhGroup> groups = null;
        URL moduli;
        String moduliStr = FactoryManagerUtils.getString(session, ServerFactoryManager.MODULI_URL);
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

        log.debug("Loaded moduli groups from {}", moduliStr);
        return groups;
    }

    protected DHG getDH(BigInteger p, BigInteger g) throws Exception {
        return (DHG) factory.create(p, g);
    }

}
