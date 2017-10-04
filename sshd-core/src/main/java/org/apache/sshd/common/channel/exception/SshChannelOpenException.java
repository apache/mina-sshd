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
package org.apache.sshd.common.channel.exception;

/**
 * Documents failure of a channel to open as expected.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshChannelOpenException extends SshChannelException {
    private static final long serialVersionUID = 3591321447714889771L;

    private final int code;

    public SshChannelOpenException(int channelId, int code, String message) {
        this(channelId, code, message, null);
    }

    public SshChannelOpenException(int channelId, int code, String message, Throwable cause) {
        super(channelId, message, cause);
        this.code = code;
    }

    /**
     * The reason code as specified by RFC 4254.
     * <ul>
     * <li>{@link org.apache.sshd.common.SshConstants#SSH_OPEN_ADMINISTRATIVELY_PROHIBITED}
     * <li>{@link org.apache.sshd.common.SshConstants#SSH_OPEN_CONNECT_FAILED}
     * <li>{@link org.apache.sshd.common.SshConstants#SSH_OPEN_UNKNOWN_CHANNEL_TYPE}
     * <li>{@link org.apache.sshd.common.SshConstants#SSH_OPEN_RESOURCE_SHORTAGE}
     * </ul>
     *
     * @return reason code; 0 if no standardized reason code is given.
     */
    public int getReasonCode() {
        return code;
    }
}
