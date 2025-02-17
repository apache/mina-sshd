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
import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;

import org.apache.sshd.client.session.AbstractClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.kex.AbstractDH;
import org.apache.sshd.common.kex.CurveSizeIndicator;
import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KeyEncapsulationMethod;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.kex.KeyExchangeFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * Base class for DHG key exchange algorithms. Implementations will only have to configure the required data on the
 * {@link org.apache.sshd.common.kex.DHG} class in the {@link #getDH()} method.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DHGClient extends AbstractDHClientKeyExchange {
    protected final DHFactory factory;
    protected AbstractDH dh;

    private KeyEncapsulationMethod.Client kemClient;

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

        KeyEncapsulationMethod kem = dh.getKeyEncapsulation();
        byte[] e;
        if (kem == null) {
            e = updateE(dh.getE());
        } else {
            kemClient = kem.getClient();
            kemClient.init();
            e = kemClient.getPublicKey();
            byte[] dhE = dh.getE();
            int l = e.length;
            e = Arrays.copyOf(e, l + dhE.length);
            System.arraycopy(dhE, 0, e, l, dhE.length);
            e = updateE(e);
        }

        Session s = getSession();
        if (log.isDebugEnabled()) {
            log.debug("init({})[{}] Send SSH_MSG_KEXDH_INIT", this, s);
        }
        Buffer buffer = s.createBuffer(SshConstants.SSH_MSG_KEXDH_INIT, e.length + Integer.SIZE);
        dh.putE(buffer, e);

        s.writePacket(buffer);
    }

    protected AbstractDH getDH() throws Exception {
        return factory.create();
    }

    @Override
    @SuppressWarnings("checkstyle:VariableDeclarationUsageDistance")
    public boolean next(int cmd, Buffer buffer) throws Exception {
        AbstractClientSession session = getClientSession();
        if (log.isDebugEnabled()) {
            log.debug("next({})[{}] process command={}",
                    this, session, KeyExchange.getSimpleKexOpcodeName(cmd));
        }

        if (cmd != SshConstants.SSH_MSG_KEXDH_REPLY) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "Protocol error: expected packet SSH_MSG_KEXDH_REPLY, got " + KeyExchange.getSimpleKexOpcodeName(cmd));
        }

        byte[] k_s = buffer.getBytes();
        byte[] f = updateF(buffer);
        byte[] sig = buffer.getBytes();

        if (kemClient == null) {
            dh.setF(f);
            k = normalize(dh.getK());
        } else {
            try {
                int l = kemClient.getEncapsulationLength();
                if (dh instanceof CurveSizeIndicator) {
                    int expectedLength = l + ((CurveSizeIndicator) dh).getByteLength();
                    if (f.length != expectedLength) {
                        throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                                "Wrong F length (should be " + expectedLength + " bytes): " + f.length);
                    }
                } else if (f.length <= l) {
                    throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                            "Strange F length: " + f.length + "  <= " + l);
                }
                dh.setF(Arrays.copyOfRange(f, l, f.length));
                Digest keyHash = dh.getHash();
                keyHash.init();
                keyHash.update(kemClient.extractSecret(Arrays.copyOf(f, l)));
                keyHash.update(dh.getK());
                k = keyHash.digest();
            } catch (IllegalArgumentException ex) {
                log.error("Key encapsulation error", ex);
                throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "Key encapsulation error: " + ex.getMessage());
            }
        }

        String keyAlg = session.getNegotiatedKexParameter(KexProposalOption.SERVERKEYS);

        boolean wantCert = KeyUtils.isCertificateAlgorithm(keyAlg);

        buffer = new ByteArrayBuffer(k_s);
        PublicKey serverKey = buffer.getRawPublicKey();
        PublicKey serverPublicHostKey = serverKey;

        if (serverKey instanceof OpenSshCertificate) {
            OpenSshCertificate openSshKey = (OpenSshCertificate) serverKey;
            if (!wantCert) {
                log.error("Got a server key certificate, but negotiated algorithm is {}", keyAlg);
                throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "OpenSshCertificate found with KEX algorithm " + keyAlg);
            }
            serverPublicHostKey = openSshKey.getCertPubKey();

            try {
                verifyCertificate(session, openSshKey);
            } catch (SshException e) {
                if (CoreModuleProperties.ABORT_ON_INVALID_CERTIFICATE.getRequired(session)) {
                    throw e;
                } else {
                    // ignore certificate
                    serverKey = openSshKey.getCertPubKey();
                    log.info("Ignoring invalid certificate {}", openSshKey.getId(), e);
                }
            }
        } else if (wantCert) {
            log.error("Got a plain public key (not a certificate) for negotiated algorithm {}", keyAlg);
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "Server did not send a certificate with KEX algorithm " + keyAlg);
        }

        buffer = new ByteArrayBuffer();
        buffer.putBytes(v_c);
        buffer.putBytes(v_s);
        buffer.putBytes(i_c);
        buffer.putBytes(i_s);
        buffer.putBytes(k_s);
        dh.putE(buffer, getE());
        dh.putF(buffer, f);
        buffer.putBytes(k);
        hash.update(buffer.array(), 0, buffer.available());
        h = hash.digest();

        Signature verif = ValidateUtils.checkNotNull(
                NamedFactory.create(session.getSignatureFactories(), keyAlg),
                "No verifier located for algorithm=%s", keyAlg);
        verif.initVerifier(session, serverPublicHostKey);
        verif.update(session, h);
        if (!verif.verify(session, sig)) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "KeyExchange signature verification failed for key type=" + keyAlg);
        }

        session.setServerKey(serverKey);
        return true;
    }

    protected void verifyCertificate(Session session, OpenSshCertificate openSshKey) throws Exception {
        PublicKey signatureKey = openSshKey.getCaPubKey();
        String keyAlg = KeyUtils.getKeyType(signatureKey);
        String keyId = openSshKey.getId();

        if (!OpenSshCertificate.Type.HOST.equals(openSshKey.getType())) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "KeyExchange signature verification failed, not a host key (2) " + openSshKey.getType() + " for key ID="
                                                                                     + keyId);
        }

        if (!OpenSshCertificate.isValidNow(openSshKey)) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "KeyExchange signature verification failed, CA expired for key ID=" + keyId);
        }

        String sigAlg = openSshKey.getSignatureAlgorithm();
        if (!keyAlg.equals(KeyUtils.getCanonicalKeyType(sigAlg))) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "Found invalid signature alg " + sigAlg + " for key ID=" + keyId + " using a " + keyAlg + " CA key");
        }

        Signature verif = ValidateUtils.checkNotNull(
                NamedFactory.create(session.getSignatureFactories(), sigAlg),
                "No KeyExchange CA verifier located for algorithm=%s of key ID=%s", sigAlg, keyId);
        verif.initVerifier(session, signatureKey);
        verif.update(session, openSshKey.getMessage());

        if (!verif.verify(session, openSshKey.getSignature())) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "KeyExchange CA signature verification failed for key type=" + keyAlg + " of key ID=" + keyId);
        }

        // "As a special case, a zero-length "valid principals" field means the certificate is valid for
        // any principal of the specified type."
        // See https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
        //
        // Empty principals in a host certificate mean the certificate is valid for any host.
        Collection<String> principals = openSshKey.getPrincipals();
        if (!GenericUtils.isEmpty(principals)) {
            /*
             * We compare only the connect address against the principals and do not do any reverse DNS lookups. If one
             * wants to connect with the IP it has to be included in the principals list of the certificate.
             */
            SocketAddress connectSocketAddress = getClientSession().getConnectAddress();
            if (connectSocketAddress instanceof SshdSocketAddress) {
                connectSocketAddress = ((SshdSocketAddress) connectSocketAddress).toInetSocketAddress();
            }

            if (connectSocketAddress instanceof InetSocketAddress) {
                String hostName = ((InetSocketAddress) connectSocketAddress).getHostString();
                if (GenericUtils.isEmpty(principals) || (!principals.contains(hostName))) {
                    throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                            "KeyExchange signature verification failed, invalid principal " + hostName + " for key ID=" + keyId
                                                                                             + " - allowed=" + principals);
                }
            } else {
                throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "KeyExchange signature verification failed, could not determine connect host for key ID=" + keyId);
            }
        }

        if (!GenericUtils.isEmpty(openSshKey.getCriticalOptions())) {
            // no critical option defined for host keys yet
            throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "KeyExchange signature verification failed, unrecognized critical options "
                                                                                     + openSshKey.getCriticalOptions()
                                                                                     + " for key ID="
                                                                                     + keyId);
        }
    }
}
