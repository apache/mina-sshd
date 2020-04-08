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

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.PublicKey;
import java.util.Objects;

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
import org.apache.sshd.common.u2f.OpenSshPublicKey;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.buffer.keys.OpenSSHCertPublicKeyParser;
import org.apache.sshd.common.util.net.SshdSocketAddress;

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

    protected DHGClient(DHFactory factory, Session session) {
        super(session);

        this.factory = Objects.requireNonNull(factory, "No factory");
    }

    @Override
    public final String getName() {
        return factory.getName();
    }

    public static KeyExchangeFactory newFactory(DHFactory delegate) {
        return new KeyExchangeFactory() {
            @Override
            public String getName() {
                return delegate.getName();
            }

            @Override
            public KeyExchange createKeyExchange(Session session) throws Exception {
                return new DHGClient(delegate, session);
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

        dh = getDH();
        hash = dh.getHash();
        hash.init();
        e = dh.getE();

        Session s = getSession();
        if (log.isDebugEnabled()) {
            log.debug("init({})[{}] Send SSH_MSG_KEXDH_INIT", this, s);
        }
        Buffer buffer =
            s.createBuffer(SshConstants.SSH_MSG_KEXDH_INIT, e.length + Integer.SIZE);
        buffer.putMPInt(e);

        s.writePacket(buffer);
    }

    protected AbstractDH getDH() throws Exception {
        return factory.create();
    }

    @Override
    @SuppressWarnings("checkstyle:VariableDeclarationUsageDistance")
    public boolean next(int cmd, Buffer buffer) throws Exception {
        Session session = getSession();
        if (log.isDebugEnabled()) {
            log.debug("next({})[{}] process command={}",
                this, session, KeyExchange.getSimpleKexOpcodeName(cmd));
        }

        if (cmd != SshConstants.SSH_MSG_KEXDH_REPLY) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                "Protocol error: expected packet SSH_MSG_KEXDH_REPLY, got " + KeyExchange.getSimpleKexOpcodeName(cmd));
        }

        byte[] k_s = buffer.getBytes();
        f = buffer.getMPIntAsBytes();
        byte[] sig = buffer.getBytes();
        dh.setF(f);
        k = dh.getK();

        buffer = new ByteArrayBuffer(k_s);
        serverKey = buffer.getRawPublicKey();

        OpenSshPublicKey openSshKey = null;
        if (serverKey instanceof OpenSshPublicKey) {
            openSshKey = (OpenSshPublicKey) serverKey;
            serverKey = openSshKey.getServerHostKey();

            byte[] data = buffer.getBytesConsumed();
            byte[] signature = buffer.getBytes();

            if (buffer.rpos() != buffer.wpos()) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "KeyExchange signature verification failed, got more data than expected: "
                                + buffer.rpos() + ", actual: " + buffer.wpos());
            }

            // verify signature
            PublicKey signatureKey = openSshKey.getCaPubKey();
            String keyAlg = KeyUtils.getKeyType(signatureKey);
            Signature verif = ValidateUtils.checkNotNull(
                    NamedFactory.create(session.getSignatureFactories(), keyAlg),
                    "No verifier located for algorithm=%s", keyAlg);
            verif.initVerifier(session, signatureKey);
            verif.update(session, data);
            if (!verif.verify(session, signature)) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "KeyExchange CA signature verification failed for key type=" + keyAlg);
            }

            if (openSshKey.getType() != OpenSSHCertPublicKeyParser.SSH_CERT_TYPE_HOST) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "KeyExchange signature verification failed, not a host key (2): "
                                + openSshKey.getType());
            }

            long now = System.currentTimeMillis() / 1000;
            if (now <= openSshKey.getValidAfter() || now >= openSshKey.getValidBefore()) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "KeyExchange signature verification failed, CA expired: "
                                + openSshKey.getValidAfter() + "-" + openSshKey.getValidBefore());
            }

            SocketAddress connectSocketAddress = getClientSession().getConnectAddress();
            if (connectSocketAddress instanceof SshdSocketAddress) {
                connectSocketAddress = ((SshdSocketAddress) connectSocketAddress).toInetSocketAddress();
            }
            if (connectSocketAddress instanceof InetSocketAddress) {
                String hostName = ((InetSocketAddress) connectSocketAddress).getHostString();
                if (!openSshKey.getPrincipals().contains(hostName)) {
                    throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                            "KeyExchange signature verification failed, invalid principal: "
                                    + openSshKey.getPrincipals());
                }
            } else {
                throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "KeyExchange signature verification failed, could not determine connect host.");
            }

            if (!openSshKey.getCriticalOptions().isEmpty()) {
                // no critical option defined for host keys yet
                throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "KeyExchange signature verification failed, unrecognized critical option: "
                                + openSshKey.getCriticalOptions());
            }
        }

        String keyAlg = KeyUtils.getKeyType(serverKey);
        if (GenericUtils.isEmpty(keyAlg)) {
            throw new SshException("Unsupported server key type: " + serverKey.getAlgorithm()
                + "[" + serverKey.getFormat() + "]");
        }

        buffer = new ByteArrayBuffer();
        buffer.putBytes(v_c);
        buffer.putBytes(v_s);
        buffer.putBytes(i_c);
        buffer.putBytes(i_s);
        buffer.putBytes(k_s);
        buffer.putMPInt(e);
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
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                "KeyExchange signature verification failed for key type=" + keyAlg);
        }

        if (openSshKey != null) {
            // replace the actual server host key with the CA pub key to be verified by the ServerKeyVerifier
            // this way we don't need to modify the ServerKeyVerifier to support @cert-authority entries
            serverKey = openSshKey.getCaPubKey();
        }

        return true;
    }
}
