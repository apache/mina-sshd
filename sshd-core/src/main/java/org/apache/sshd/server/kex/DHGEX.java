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

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.common.Digest;
import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Random;
import org.apache.sshd.common.Signature;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.digest.SHA1;
import org.apache.sshd.common.kex.DH;
import org.apache.sshd.common.kex.DHGroupData;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.BufferUtils;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Server side Diffie Hellman Group Exchange
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DHGEX implements KeyExchange {

    public static class Factory implements NamedFactory<KeyExchange> {

        public String getName() {
            return "diffie-hellman-group-exchange-sha1";
        }

        public KeyExchange create() {
            return new DHGEX();
        }

    }

    private final Logger log = LoggerFactory.getLogger(getClass());

    private ServerSession session;
    private byte[] V_S;
    private byte[] V_C;
    private byte[] I_S;
    private byte[] I_C;
    private Digest hash;
    private DH dh;
    private byte[] e;
    private byte[] f;
    private byte[] K;
    private byte[] H;

    int min;
    int prf;
    int max;
    private byte expected;
    boolean oldRequest;

    public void init(AbstractSession s, byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception {
        if (!(s instanceof ServerSession)) {
            throw new IllegalStateException("Using a server side KeyExchange on a client");
        }
        session = (ServerSession) s;
        this.V_S = V_S;
        this.V_C = V_C;
        this.I_S = I_S;
        this.I_C = I_C;

        expected = SshConstants.SSH_MSG_KEX_DH_GEX_REQUEST;
    }

    public boolean next(Buffer buffer) throws Exception {
        byte cmd = buffer.getByte();

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
        if (cmd != expected) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "Protocol error: expected packet " + expected + ", got " + cmd);
        }

        if (cmd == SshConstants.SSH_MSG_KEX_DH_GEX_INIT) {
            log.debug("Received SSH_MSG_KEX_DH_GEX_INIT");
            e = buffer.getMPIntAsBytes();
            dh.setF(e);
            K = dh.getK();


            byte[] K_S;
            KeyPair kp = session.getHostKey();
            String algo = session.getNegotiated(SshConstants.PROPOSAL_SERVER_HOST_KEY_ALGS);
            Signature sig = NamedFactory.Utils.create(session.getFactoryManager().getSignatureFactories(), algo);
            sig.init(kp.getPublic(), kp.getPrivate());

            buffer = new Buffer();
            buffer.putRawPublicKey(kp.getPublic());
            K_S = buffer.getCompactData();

            buffer.clear();
            buffer.putString(V_C);
            buffer.putString(V_S);
            buffer.putString(I_C);
            buffer.putString(I_S);
            buffer.putString(K_S);
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
            buffer.putMPInt(K);
            hash.update(buffer.array(), 0, buffer.available());
            H = hash.digest();

            byte[] sigH;
            buffer.clear();
            sig.update(H, 0, H.length);
            buffer.putString(algo);
            buffer.putString(sig.sign());
            sigH = buffer.getCompactData();

            if (log.isDebugEnabled()) {
                log.debug("K_S:  {}", BufferUtils.printHex(K_S));
                log.debug("f:    {}", BufferUtils.printHex(f));
                log.debug("sigH: {}", BufferUtils.printHex(sigH));
            }

            // Send response
            log.debug("Send SSH_MSG_KEX_DH_GEX_REPLY");
            buffer.clear();
            buffer.rpos(5);
            buffer.wpos(5);
            buffer.putByte(SshConstants.SSH_MSG_KEX_DH_GEX_REPLY);
            buffer.putString(K_S);
            buffer.putString(f);
            buffer.putString(sigH);
            session.writePacket(buffer);
            return true;
        }

        return false;
    }

    private DH chooseDH(int min, int prf, int max) throws Exception {
        List<Moduli.DhGroup> groups = null;
        URL moduli;
        String moduliStr = session.getFactoryManager().getProperties().get(ServerFactoryManager.MODULI_URL);
        if (moduliStr != null) {
            try {
                moduli = new URL(moduliStr);
                groups = Moduli.parseModuli(moduli);
            } catch (IOException e) {
                log.warn("Error loading external moduli", e);
            }
        }
        if (groups == null) {
            moduli = getClass().getResource("/org/apache/sshd/moduli");
            groups = Moduli.parseModuli(moduli);
        }

        min = Math.max(min, 1024);
        prf = Math.max(prf, 1024);
        // Keys of size > 1024 are not support by default with JCE, so only enable
        // those if BouncyCastle is registered
        prf = Math.min(prf, SecurityUtils.isBouncyCastleRegistered() ? 8192 : 1024);
        max = Math.min(max, 8192);
        int bestSize = 0;
        List<Moduli.DhGroup> selected = new ArrayList<Moduli.DhGroup>();
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

    protected DH getDH(BigInteger p, BigInteger g) throws Exception {
        DH dh = new DH(new SHA1.Factory());
        dh.setP(p);
        dh.setG(g);
        return dh;
    }

    public Digest getHash() {
        return hash;
    }

    public byte[] getH() {
        return H;
    }

    public byte[] getK() {
        return K;
    }

    public PublicKey getServerKey() {
        return session.getHostKey().getPublic();
    }

}
