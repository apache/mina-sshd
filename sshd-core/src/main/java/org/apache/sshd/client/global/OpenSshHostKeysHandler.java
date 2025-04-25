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

package org.apache.sshd.client.global;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.UnsupportedSshPublicKey;
import org.apache.sshd.common.global.AbstractOpenSshHostKeysHandler;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferException;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.buffer.keys.BufferPublicKeyParser;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * A handler for the "hostkeys-00@openssh.com" request.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <a href="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL">OpenSSH protocol - section 2.5</a>
 */
public class OpenSshHostKeysHandler extends AbstractOpenSshHostKeysHandler {
    public static final String REQUEST = "hostkeys-00@openssh.com";
    public static final OpenSshHostKeysHandler INSTANCE = new OpenSshHostKeysHandler();

    public OpenSshHostKeysHandler() {
        super(REQUEST);
        setIgnoreInvalidKeys(true);
    }

    public OpenSshHostKeysHandler(BufferPublicKeyParser<? extends PublicKey> parser) {
        super(REQUEST, parser);
        setIgnoreInvalidKeys(true);
    }

    @Override
    protected Result handleHostKeys(Session session, Collection<PublicKey> keys, boolean wantReply, Buffer buffer)
            throws Exception {
        // according to the spec, no reply should be required
        ValidateUtils.checkTrue(!wantReply, "Unexpected reply required for the host keys of %s", session);
        if (log.isDebugEnabled()) {
            log.debug("handleHostKeys({})[want-reply={}] received {} keys",
                    session, wantReply, GenericUtils.size(keys));
        }
        // Build and send the signature request, then verify signatures.
        ClientSession client = ValidateUtils.checkInstanceOf(session, ClientSession.class,
                "handleHostKeys(%s) called on a ServerSession", session);
        List<PublicKey> validKeys = keys.stream().filter(key -> {
            if (key instanceof OpenSshCertificate) {
                return isValidHostCertificate(client, (OpenSshCertificate) key);
            }
            return !(key instanceof UnsupportedSshPublicKey);
        }).collect(Collectors.toList());
        Buffer request = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST);
        request.putString(org.apache.sshd.server.global.OpenSshHostKeysHandler.REQUEST);
        request.putBoolean(true); // want-reply
        validKeys.forEach(request::putPublicKey);
        client.request(request, org.apache.sshd.server.global.OpenSshHostKeysHandler.REQUEST,
                (cmd, reply) -> {
                    if (cmd == SshConstants.SSH_MSG_REQUEST_SUCCESS) {
                        handleHostKeyRotation(client, validKeys, reply);
                    }
                });
        return Result.Replied;
    }

    protected void handleHostKeyRotation(ClientSession client, List<PublicKey> proposedKeys, Buffer reply) {
        List<PublicKey> newKeys = new ArrayList<>();
        proposedKeys.forEach(k -> {
            byte[] signature = reply.getBytes();
            String keyType = KeyUtils.getKeyType(k);
            PublicKey signingKey = k;
            if (k instanceof OpenSshCertificate) {
                signingKey = ((OpenSshCertificate) k).getCertPubKey();
            }
            String algo = KeyUtils.getKeyType(signingKey);
            // RSA is special...
            if (KeyPairProvider.SSH_RSA.equals(algo)) {
                // If a RSA host key was negotiated in KEX, use the signature algorithm from there:
                String negotiated = client.getKexNegotiationResult().get(KexProposalOption.ALGORITHMS);
                String canonical = KeyUtils.getCanonicalKeyType(negotiated);
                if (KeyPairProvider.SSH_RSA.equals(canonical) || KeyPairProvider.SSH_RSA_CERT.equals(canonical)) {
                    algo = KeyUtils.getSignatureAlgorithm(negotiated);
                } else {
                    // Look at what kind of signature we have. We accept only RSA_SHA256/512
                    Buffer sigBuf = new ByteArrayBuffer(signature);
                    try {
                        algo = sigBuf.getString();
                        if (KeyPairProvider.SSH_RSA.equals(algo)
                                || !KeyPairProvider.SSH_RSA.equals(KeyUtils.getCanonicalKeyType(algo))) {
                            return;
                        }
                    } catch (BufferException e) {
                        if (log.isDebugEnabled()) {
                            log.debug("handleHostKeyRotation({}) ignoring {} key because signature data is invalid", client,
                                    keyType);
                        }
                        return;
                    }
                }
            }
            // Verify the signature.
            Signature verifier = NamedFactory.create(client.getSignatureFactories(), algo);
            if (verifier == null) {
                if (log.isDebugEnabled()) {
                    log.debug("handleHostKeyRotation({}) ignoring {} key because no signature verifier for {}", client, keyType,
                            algo);
                }
                return;
            }
            Buffer expected = new ByteArrayBuffer();
            expected.putString(org.apache.sshd.server.global.OpenSshHostKeysHandler.REQUEST);
            expected.putBytes(client.getSessionId());
            expected.putPublicKey(k);
            byte[] data = expected.getCompactData();
            try {
                verifier.initVerifier(client, signingKey);
                verifier.update(client, data);
                if (!verifier.verify(client, signature)) {
                    if (log.isDebugEnabled()) {
                        log.debug("handleHostKeyRotation({}) ignoring {} key because {} signature doesn't match", client,
                                keyType, algo);
                    }
                    return;
                }
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug("handleHostKeyRotation({}) ignoring {} key: exception during {} signature verification: {}",
                            client, keyType, algo, e.toString());
                }
                return;
            }
            newKeys.add(k);
        });
        if (reply.available() > 0) {
            log.warn("handleHostKeyRotation({}) extra data of {} bytes ignored", client, reply.available());
        }
        if (!newKeys.isEmpty()) {
            client.getFactoryManager().getNewHostKeysHandler().receiveNewHostKeys(client, newKeys);
        }
    }

    private boolean isValidHostCertificate(ClientSession session, OpenSshCertificate cert) {
        if (!OpenSshCertificate.Type.HOST.equals(cert.getType()) || !OpenSshCertificate.isValidNow(cert)
                || !cert.getCriticalOptions().isEmpty()) {
            return false;
        }
        try {
            if (!OpenSshCertificate.verifySignature(cert, session.getSignatureFactories())) {
                return false;
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("isValidHostCertificate({}) could not verify host ertificate signature; got {}", session,
                        e.toString());
            }
            return false;
        }
        // Empty principals in a host certificate mean the certificate is valid for any host.
        Collection<String> principals = cert.getPrincipals();
        if (!GenericUtils.isEmpty(principals)) {
            /*
             * We compare only the connect address against the principals and do not do any reverse DNS lookups. If one
             * wants to connect with the IP it has to be included in the principals list of the certificate.
             */
            SocketAddress connectSocketAddress = session.getConnectAddress();
            String hostName = null;
            if (connectSocketAddress instanceof SshdSocketAddress) {
                hostName = ((SshdSocketAddress) connectSocketAddress).getHostName();
            } else if (connectSocketAddress instanceof InetSocketAddress) {
                hostName = ((InetSocketAddress) connectSocketAddress).getHostString();
            }
            return hostName != null && principals.contains(hostName);
        }
        return true;
    }
}
