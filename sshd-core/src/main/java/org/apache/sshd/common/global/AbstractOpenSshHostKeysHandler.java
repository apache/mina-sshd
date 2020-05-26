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

package org.apache.sshd.common.global;

import java.security.PublicKey;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Objects;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.helpers.AbstractConnectionServiceRequestHandler;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.keys.BufferPublicKeyParser;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractOpenSshHostKeysHandler extends AbstractConnectionServiceRequestHandler {
    private final String request;
    private final BufferPublicKeyParser<? extends PublicKey> parser;

    protected AbstractOpenSshHostKeysHandler(String request) {
        this(request, BufferPublicKeyParser.DEFAULT);
    }

    protected AbstractOpenSshHostKeysHandler(
                                             String request, BufferPublicKeyParser<? extends PublicKey> parser) {
        this.request = ValidateUtils.checkNotNullAndNotEmpty(request, "No request identifier");
        this.parser = Objects.requireNonNull(parser, "No public keys extractor");
    }

    public final String getRequestName() {
        return request;
    }

    public BufferPublicKeyParser<? extends PublicKey> getPublicKeysParser() {
        return parser;
    }

    @Override
    public Result process(
            ConnectionService connectionService, String request, boolean wantReply, Buffer buffer)
            throws Exception {
        String expected = getRequestName();
        if (!expected.equals(request)) {
            return super.process(connectionService, request, wantReply, buffer);
        }

        Collection<PublicKey> keys = new LinkedList<>();
        BufferPublicKeyParser<? extends PublicKey> p = getPublicKeysParser();
        if (p != null) {
            boolean debugEnabled = log.isDebugEnabled();
            while (buffer.available() > 0) {
                PublicKey key = buffer.getPublicKey(p);
                if (debugEnabled) {
                    log.debug("process({})[{}] key type={}, fingerprint={}",
                            connectionService, request, KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
                }
                if (key != null) {
                    keys.add(key);
                }
            }
        }

        return handleHostKeys(connectionService.getSession(), keys, wantReply, buffer);
    }

    protected abstract Result handleHostKeys(
            Session session, Collection<? extends PublicKey> keys, boolean wantReply, Buffer buffer)
            throws Exception;

    @Override
    public String toString() {
        return getRequestName();
    }
}
