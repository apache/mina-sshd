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

import java.security.PublicKey;
import java.util.Collection;

import org.apache.sshd.common.global.AbstractOpenSshHostKeysHandler;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.keys.BufferPublicKeyParser;

/**
 * A handler for the &quot;hostkeys-00@openssh.com&quot; request - for now, only reads the presented host key. One can
 * override the {@link #handleHostKeys(Session, Collection, boolean, Buffer)} methods in order to do something with the
 * keys
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <a href="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL">OpenSSH protocol - section 2.5</a>
 */
public class OpenSshHostKeysHandler extends AbstractOpenSshHostKeysHandler {
    public static final String REQUEST = "hostkeys-00@openssh.com";
    public static final OpenSshHostKeysHandler INSTANCE = new OpenSshHostKeysHandler();

    public OpenSshHostKeysHandler() {
        super(REQUEST);
    }

    public OpenSshHostKeysHandler(BufferPublicKeyParser<? extends PublicKey> parser) {
        super(REQUEST, parser);
    }

    @Override
    protected Result handleHostKeys(
            Session session, Collection<? extends PublicKey> keys, boolean wantReply, Buffer buffer)
            throws Exception {
        // according to the spec, no reply should be required
        ValidateUtils.checkTrue(!wantReply, "Unexpected reply required for the host keys of %s", session);
        if (log.isDebugEnabled()) {
            log.debug("handleHostKeys({})[want-reply={}] received {} keys",
                    session, wantReply, GenericUtils.size(keys));
        }

        return Result.Replied;
    }
}
