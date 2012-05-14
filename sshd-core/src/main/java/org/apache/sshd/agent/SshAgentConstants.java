package org.apache.sshd.agent;

public final class SshAgentConstants {

    public static final byte SSH_AGENT_SUCCESS = 6;
    public static final byte SSH2_AGENTC_REQUEST_IDENTITIES = 11;
    public static final byte SSH2_AGENT_IDENTITIES_ANSWER = 12;
    public static final byte SSH2_AGENTC_SIGN_REQUEST = 13;
    public static final byte SSH2_AGENT_SIGN_RESPONSE = 14;
    public static final byte SSH2_AGENTC_ADD_IDENTITY = 17;
    public static final byte SSH2_AGENTC_REMOVE_IDENTITY = 18;
    public static final byte SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19;
    public static final byte SSH2_AGENT_FAILURE = 30;

    private SshAgentConstants() {
    }

}
