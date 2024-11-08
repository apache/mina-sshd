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
package org.apache.sshd.client.channel;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Future;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.threads.CloseableExecutorService;

/**
 * Client side channel session
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelSession extends AsyncCapableClientChannel {

    protected CloseableExecutorService pumperService;
    protected Future<?> pumper;
    private final Map<String, Object> env = new LinkedHashMap<>();

    public ChannelSession() {
        super("session", true);
    }

    @Override
    protected RequestHandler.Result handleInternalRequest(String req, boolean wantReply, Buffer buffer)
            throws IOException {
        switch (req) {
            case "xon-xoff":
                return handleXonXoff(buffer, wantReply);
            default:
                return super.handleInternalRequest(req, wantReply, buffer);
        }
    }

    // see RFC4254 section 6.8
    protected RequestHandler.Result handleXonXoff(Buffer buffer, boolean wantReply) throws IOException {
        boolean clientCanDo = buffer.getBoolean();
        if (log.isDebugEnabled()) {
            log.debug("handleXonXoff({})[want-reply={}] client-can-do={}", this, wantReply, clientCanDo);
        }

        return RequestHandler.Result.ReplySuccess;
    }

    /**
     * @param  key   The (never {@code null}) key (Note: may be empty...)
     * @param  value The value to set - if {@code null} then the pre-existing value for the key (if any) is
     *               <U>removed</U>.
     * @return       The replaced/removed previous value - {@code null} if no previous value set for the key.
     */
    public Object setEnv(String key, Object value) {
        ValidateUtils.checkNotNull(key, "No key provided");
        if (value == null) {
            return env.remove(key);
        } else {
            return env.put(key, value);
        }
    }

    protected void sendEnvVariables(Session session) throws IOException {
        if (MapEntryUtils.size(env) > 0) {
            if (log.isDebugEnabled()) {
                log.debug("Sending env variables ({}) Send SSH_MSG_CHANNEL_REQUEST env: {}", this, env);
            }

            // Cannot use forEach because of the IOException being thrown by writePacket
            for (Map.Entry<String, ?> entry : env.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                String str = Objects.toString(value);
                Buffer buffer = session.createBuffer(
                        SshConstants.SSH_MSG_CHANNEL_REQUEST, key.length() + GenericUtils.length(str) + Integer.SIZE);
                buffer.putInt(getRecipient());
                buffer.putString("env");
                buffer.putBoolean(false); // want-reply
                buffer.putString(key);
                buffer.putString(str);
                writePacket(buffer);
            }
        }
    }
}
