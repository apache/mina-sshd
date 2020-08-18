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

package org.apache.sshd.server.auth.hostbased;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactoriesManager;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.auth.AbstractUserAuth;
import org.apache.sshd.server.session.ServerSession;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthHostBased extends AbstractUserAuth implements SignatureFactoriesManager {
    public static final String NAME = UserAuthHostBasedFactory.NAME;

    private List<NamedFactory<Signature>> factories;

    public UserAuthHostBased() {
        this(null);
    }

    public UserAuthHostBased(List<NamedFactory<Signature>> factories) {
        super(NAME);
        this.factories = factories; // OK if null/empty
    }

    @Override
    public List<NamedFactory<Signature>> getSignatureFactories() {
        return factories;
    }

    @Override
    public void setSignatureFactories(List<NamedFactory<Signature>> factories) {
        this.factories = factories;
    }

    @Override
    @SuppressWarnings("checkstyle:VariableDeclarationUsageDistance")
    protected Boolean doAuth(Buffer buffer, boolean init) throws Exception {
        ValidateUtils.checkTrue(init, "Instance not initialized");

        int dataLen = buffer.available();
        String username = getUsername();
        ServerSession session = getSession();
        String keyType = buffer.getString();
        int keyLen = buffer.getInt();
        int keyOffset = buffer.rpos();
        int remaining = buffer.available();
        // Protect against malicious or corrupted packets
        if ((keyLen < 0) || (keyLen > remaining)) {
            log.error("doAuth({}@{}) Illogical {} key length={} (max. available={})",
                    username, session, keyType, keyLen, remaining);
            throw new IndexOutOfBoundsException("Illogical " + keyType + " key length: " + keyLen);
        }

        Buffer buf = new ByteArrayBuffer(buffer.array(), keyOffset, keyLen, true);
        PublicKey clientKey = buf.getRawPublicKey();
        List<X509Certificate> certs = Collections.emptyList();
        remaining = buf.available();
        if (remaining > 0) {
            CertificateFactory cf = SecurityUtils.getCertificateFactory("X.509");
            certs = new ArrayList<>();
            try (ByteArrayInputStream bais = new ByteArrayInputStream(buf.array(), buf.rpos(), remaining)) {
                X509Certificate c = (X509Certificate) cf.generateCertificate(bais);
                certs.add(c);
            }
        }

        buffer.rpos(keyOffset + keyLen);
        String clientHostName = buffer.getString();
        String clientUsername = buffer.getString();

        byte[] signature = buffer.getBytes();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("doAuth({}@{}) authenticate key type={}, fingerprint={}, client={}@{}, num-certs={}",
                    username, session, keyType, KeyUtils.getFingerPrint(clientKey),
                    clientUsername, clientHostName, GenericUtils.size(certs));
        }

        HostBasedAuthenticator authenticator = session.getHostBasedAuthenticator();
        if (authenticator == null) {
            if (debugEnabled) {
                log.debug("doAuth({}@{}) key type={}, fingerprint={}, client={}@{}, num-certs={} - no authenticator",
                        username, session, keyType, KeyUtils.getFingerPrint(clientKey),
                        clientUsername, clientHostName, GenericUtils.size(certs));
            }
            return Boolean.FALSE;
        }

        boolean authed;
        try {
            authed = authenticator.authenticate(
                    session, username, clientKey, clientHostName, clientUsername, certs);
        } catch (Error e) {
            warn("doAuth({}@{}) failed ({}) to consult authenticator for {} key={}: {}",
                    username, session, e.getClass().getSimpleName(),
                    keyType, KeyUtils.getFingerPrint(clientKey), e.getMessage(), e);
            throw new RuntimeSshException(e);
        }

        if (debugEnabled) {
            log.debug("doAuth({}@{}) key type={}, fingerprint={}, client={}@{}, num-certs={} - authentication result: {}",
                    username, session, keyType, KeyUtils.getFingerPrint(clientKey),
                    clientUsername, clientHostName, GenericUtils.size(certs), authed);
        }
        if (!authed) {
            return Boolean.FALSE;
        }

        // verify signature
        Collection<NamedFactory<Signature>> factories = ValidateUtils.checkNotNullAndNotEmpty(
                SignatureFactoriesManager.resolveSignatureFactories(this, session),
                "No signature factories for session=%s",
                session);
        Signature verifier = ValidateUtils.checkNotNull(
                NamedFactory.create(factories, keyType),
                "No verifier located for algorithm=%s",
                keyType);
        verifier.initVerifier(session, clientKey);

        byte[] id = session.getSessionId();
        buf = new ByteArrayBuffer(dataLen + id.length + Long.SIZE, false);
        buf.putBytes(id);
        buf.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
        buf.putString(username);
        buf.putString(getService());
        buf.putString(getName());
        buf.putString(keyType);
        buf.putInt(keyLen);
        // copy the key + certificates
        buf.putRawBytes(buffer.array(), keyOffset, keyLen);
        buf.putString(clientHostName);
        buf.putString(clientUsername);

        if (log.isTraceEnabled()) {
            log.trace("doAuth({}@{}) key type={}, fingerprint={}, client={}@{}, num-certs={} - verification data: {}",
                    username, session, keyType, KeyUtils.getFingerPrint(clientKey),
                    clientUsername, clientHostName, GenericUtils.size(certs), buf.toHex());
            log.trace("doAuth({}@{}) key type={}, fingerprint={}, client={}@{}, num-certs={} - expected signature: {}",
                    username, session, keyType, KeyUtils.getFingerPrint(clientKey),
                    clientUsername, clientHostName, GenericUtils.size(certs), BufferUtils.toHex(signature));
        }

        verifier.update(session, buf.array(), buf.rpos(), buf.available());
        if (!verifier.verify(session, signature)) {
            throw new SignatureException("Key verification failed");
        }

        if (debugEnabled) {
            log.debug("doAuth({}@{}) key type={}, fingerprint={}, client={}@{}, num-certs={} - verified signature",
                    username, session, keyType, KeyUtils.getFingerPrint(clientKey),
                    clientUsername, clientHostName, GenericUtils.size(certs));
        }
        return Boolean.TRUE;
    }
}
