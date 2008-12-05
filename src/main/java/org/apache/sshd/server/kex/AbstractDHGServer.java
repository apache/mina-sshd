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

import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.Digest;
import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Signature;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.digest.SHA1;
import org.apache.sshd.common.kex.DH;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.BufferUtils;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public abstract class AbstractDHGServer implements KeyExchange {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private ServerSession session;
    private byte[] V_S;
    private byte[] V_C;
    private byte[] I_S;
    private byte[] I_C;
    private Digest sha;
    private DH dh;
    private byte[] e;
    private byte[] f;
    private byte[] K;
    private byte[] H;

    public void init(AbstractSession s, byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception {
        if (!(s instanceof ServerSession)) {
            throw new IllegalStateException("Using a server side KeyExchange on a client");
        }
        session = (ServerSession) s;
        this.V_S = V_S;
        this.V_C = V_C;
        this.I_S = I_S;
        this.I_C = I_C;
        sha = new SHA1();
        sha.init();
        dh = new DH();
        initDH(dh);
        f = dh.getE();
    }

    protected abstract void initDH(DH dh);

    public boolean next(Buffer buffer) throws Exception {
        SshConstants.Message cmd = buffer.getCommand();
        if (cmd != SshConstants.Message.SSH_MSG_KEXDH_INIT) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, 
                                   "Protocol error: expected packet " + SshConstants.Message.SSH_MSG_KEXDH_INIT + ", got " + cmd);
        }
        log.info("Received SSH_MSG_KEXDH_INIT");
        e = buffer.getMPIntAsBytes();
        dh.setF(e);
        K = dh.getK();

        byte[] K_S;
        KeyPair kp = session.getHostKey();
        String algo = session.getNegociated(SshConstants.PROPOSAL_SERVER_HOST_KEY_ALGS);
        Signature sig = NamedFactory.Utils.create(session.getFactoryManager().getSignatureFactories(), algo);
        sig.init(kp.getPublic(), kp.getPrivate());

        buffer = new Buffer();
        buffer.putPublicKey(kp.getPublic());
        K_S = buffer.getCompactData();

        buffer.clear();
        buffer.putString(V_C);
        buffer.putString(V_S);
        buffer.putString(I_C);
        buffer.putString(I_S);
        buffer.putString(K_S);
        buffer.putMPInt(e);
        buffer.putMPInt(f);
        buffer.putMPInt(K);
        sha.update(buffer.array(), 0, buffer.available());
        H = sha.digest();

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
        log.info("Send SSH_MSG_KEXDH_REPLY");
        buffer.clear();
        buffer.rpos(5);
        buffer.wpos(5);
        buffer.putCommand(SshConstants.Message.SSH_MSG_KEXDH_REPLY_KEX_DH_GEX_GROUP);
        buffer.putString(K_S);
        buffer.putString(f);
        buffer.putString(sigH);
        session.writePacket(buffer);
        return true;
    }

    public Digest getHash() {
        return sha;
    }

    public byte[] getH() {
        return H;
    }

    public byte[] getK() {
        return K;
    }

}
