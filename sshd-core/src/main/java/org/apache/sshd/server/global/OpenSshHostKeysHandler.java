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

package org.apache.sshd.server.global;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.global.AbstractOpenSshHostKeysHandler;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactoriesManager;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.buffer.keys.BufferPublicKeyParser;
import org.apache.sshd.server.session.ServerSession;

/**
 * An initial handler for &quot;hostkeys-prove-00@openssh.com&quot; request
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <a href="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL">OpenSSH protocol - section 2.5</a>
 */
public class OpenSshHostKeysHandler extends AbstractOpenSshHostKeysHandler implements SignatureFactoriesManager {
    public static final String REQUEST = "hostkeys-prove-00@openssh.com";
    public static final OpenSshHostKeysHandler INSTANCE = new OpenSshHostKeysHandler() {
        @Override
        public List<NamedFactory<Signature>> getSignatureFactories() {
            return null;
        }

        @Override
        public void setSignatureFactories(List<NamedFactory<Signature>> factories) {
            if (!GenericUtils.isEmpty(factories)) {
                throw new UnsupportedOperationException("Not allowed to change default instance signature factories");
            }
        }
    };

    private List<NamedFactory<Signature>> factories;

    public OpenSshHostKeysHandler() {
        super(REQUEST);
    }

    public OpenSshHostKeysHandler(BufferPublicKeyParser<? extends PublicKey> parser) {
        super(REQUEST, parser);
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
    protected Result handleHostKeys(
            Session session, Collection<? extends PublicKey> keys, boolean wantReply, Buffer buffer)
            throws Exception {
        // according to the specification there MUST be reply required by the server
        ValidateUtils.checkTrue(wantReply, "No reply required for host keys of %s", session);
        Collection<? extends NamedFactory<Signature>> factories = ValidateUtils.checkNotNullAndNotEmpty(
                SignatureFactoriesManager.resolveSignatureFactories(this, session),
                "No signature factories available for host keys of session=%s",
                session);
        if (log.isDebugEnabled()) {
            log.debug("handleHostKeys({})[want-reply={}] received {} keys - factories={}",
                    session, wantReply, GenericUtils.size(keys), NamedResource.getNames(factories));
        }

        // generate the required signatures
        buffer = session.createBuffer(SshConstants.SSH_MSG_REQUEST_SUCCESS);

        Buffer buf = new ByteArrayBuffer();
        byte[] sessionId = session.getSessionId();
        KeyPairProvider kpp = Objects.requireNonNull(
                ((ServerSession) session).getKeyPairProvider(), "No server keys provider");
        for (PublicKey k : keys) {
            String keyType = KeyUtils.getKeyType(k);
            Signature verifier = ValidateUtils.checkNotNull(
                    NamedFactory.create(factories, keyType),
                    "No signer could be located for key type=%s",
                    keyType);

            KeyPair kp;
            try {
                kp = ValidateUtils.checkNotNull(kpp.loadKey(session, keyType), "No key of type=%s available", keyType);
            } catch (Error e) {
                warn("handleHostKeys({}) failed ({}) to load key of type={}: {}",
                        session, e.getClass().getSimpleName(), keyType, e.getMessage(), e);
                throw new RuntimeSshException(e);
            }
            verifier.initSigner(session, kp.getPrivate());

            buf.clear();
            buf.putString(REQUEST);
            buf.putBytes(sessionId);
            buf.putPublicKey(k);

            byte[] data = buf.getCompactData();
            verifier.update(session, data);

            byte[] signature = verifier.sign(session);
            buffer.putBytes(signature);
        }

        session.writePacket(buffer);
        return Result.Replied;
    }
}
