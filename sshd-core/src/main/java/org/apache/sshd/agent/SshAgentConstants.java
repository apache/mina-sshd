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
package org.apache.sshd.agent;

import java.util.Map;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.LoggingUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent">OpenSSH agent protocol</A>
 */
public final class SshAgentConstants {
    // Generic replies from agent to client
    public static final byte SSH_AGENT_FAILURE = 5;
    public static final byte SSH_AGENT_SUCCESS = 6;

    // Replies from agent to client for protocol 1 key operations
    public static final byte SSH_AGENT_RSA_IDENTITIES_ANSWER = 2;
    public static final byte SSH_AGENT_RSA_RESPONSE = 4;

    // Requests from client to agent for protocol 1 key operations
    public static final byte SSH_AGENTC_REQUEST_RSA_IDENTITIES = 1;
    public static final byte SSH_AGENTC_RSA_CHALLENGE = 3;
    public static final byte SSH_AGENTC_ADD_RSA_IDENTITY = 7;
    public static final byte SSH_AGENTC_REMOVE_RSA_IDENTITY = 8;
    public static final byte SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES = 9;
    public static final byte SSH_AGENTC_ADD_RSA_ID_CONSTRAINED = 24;

    // Requests from client to agent for protocol 2 key operations
    public static final byte SSH2_AGENTC_REQUEST_IDENTITIES = 11;
    public static final byte SSH2_AGENTC_SIGN_REQUEST = 13;
    public static final byte SSH2_AGENTC_ADD_IDENTITY = 17;
    public static final byte SSH2_AGENTC_REMOVE_IDENTITY = 18;
    public static final byte SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19;
    public static final byte SSH2_AGENTC_ADD_ID_CONSTRAINED = 25;

    // Key-type independent requests from client to agent
    public static final byte SSH_AGENTC_ADD_SMARTCARD_KEY = 20;
    public static final byte SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21;
    public static final byte SSH_AGENTC_LOCK = 22;
    public static final byte SSH_AGENTC_UNLOCK = 23;
    public static final byte SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26;

    public static final byte SSH2_AGENT_FAILURE = 30;

    // Replies from agent to client for protocol 2 key operations
    public static final byte SSH2_AGENT_IDENTITIES_ANSWER = 12;
    public static final byte SSH2_AGENT_SIGN_RESPONSE = 14;

    // Key constraint identifiers
    public static final byte SSH_AGENT_CONSTRAIN_LIFETIME = 1;
    public static final byte SSH_AGENT_CONSTRAIN_CONFIRM = 2;

    // Packet types defined by IETF (https://tools.ietf.org/html/draft-ietf-secsh-agent-02)
    // Messages sent by the client
    public static final int SSH_AGENT_LIST_KEYS = 204;
    public static final int SSH_AGENT_PRIVATE_KEY_OP = 205;
    // Messages sent by the agent
    public static final byte SSH_AGENT_KEY_LIST = 104;
    public static final byte SSH_AGENT_OPERATION_COMPLETE = 105;

    private SshAgentConstants() {
        throw new UnsupportedOperationException("N/A instance");
    }

    private static final class LazyMessagesMapHolder {
        private static final Map<Integer, String> MESSAGES_MAP
                = LoggingUtils.generateMnemonicMap(SshAgentConstants.class, f -> {
                    String name = f.getName();
                    return !name.startsWith("SSH_AGENT_CONSTRAIN")
                            && (name.startsWith("SSH_AGENT") || name.startsWith("SSH2_AGENT"));

                });

        private LazyMessagesMapHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    /**
     * Converts a command value to a user-friendly name
     *
     * @param  cmd The command value
     * @return     The user-friendly name - if not one of the defined {@code SSH2_AGENT} values then returns the string
     *             representation of the command's value
     */
    public static String getCommandMessageName(int cmd) {
        @SuppressWarnings("synthetic-access")
        String name = LazyMessagesMapHolder.MESSAGES_MAP.get(cmd);
        if (GenericUtils.isEmpty(name)) {
            return Integer.toString(cmd);
        } else {
            return name;
        }
    }
}
