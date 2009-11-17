/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.server.channel;

import org.apache.sshd.common.SshConstants;

/**
 * Documents failure of a channel to open as expected.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class OpenChannelException extends Exception {
    private final int code;

    public OpenChannelException(int code, String message) {
        this(code, message, null);
    }

    public OpenChannelException(int code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    /**
     * The reason code as specified by RFC 4254.
     * <ul>
     * <li>{@link SshConstants#SSH_OPEN_ADMINISTRATIVELY_PROHIBITED}
     * <li>{@link SshConstants#SSH_OPEN_CONNECT_FAILED}
     * <li>{@link SshConstants#SSH_OPEN_UNKNOWN_CHANNEL_TYPE}
     * <li>{@link SshConstants#SSH_OPEN_RESOURCE_SHORTAGE}
     * </ul>
     *
     * @return reason code; 0 if no standardized reason code is given.
     */
    public int getReasonCode() {
        return code;
    }
}
