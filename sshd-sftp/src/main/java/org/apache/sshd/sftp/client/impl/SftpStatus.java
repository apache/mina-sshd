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
package org.apache.sshd.sftp.client.impl;

import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpException;

/**
 * A representation of a SSH_FXP_STATUS record.
 */
public final class SftpStatus {

    private final int statusCode;

    private final String language;

    private final String message;

    private SftpStatus(int statusCode, String message, String language) {
        this.statusCode = statusCode;
        this.message = message;
        this.language = language;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getLanguage() {
        return language;
    }

    public String getMessage() {
        return message;
    }

    public boolean isOk() {
        return statusCode == SftpConstants.SSH_FX_OK;
    }

    @Override
    public String toString() {
        return "SSH_FXP_STATUS[" + SftpConstants.getStatusName(statusCode) + ", language=" + language + ", message=" + message
               + ']';
    }

    static SftpStatus parse(Buffer buffer) {
        int code = buffer.getInt();
        // Treat the message and language tag as optional. These fields did not exist in SFTP v0-2, and there are
        // apparently SFTP v3 servers that sometimes send SSH_FXP_STATUS without them.
        String message = buffer.available() > 0 ? buffer.getString() : null;
        String language = buffer.available() > 0 ? buffer.getString() : null;
        return new SftpStatus(code, message, language);
    }

    public static SftpStatus parse(SftpResponse response) throws SftpException {
        if (response.getType() != SftpConstants.SSH_FXP_STATUS) {
            throw new SftpException(
                    SftpConstants.SSH_FX_BAD_MESSAGE, "Unexpected SFTP response: expected SSH_FXP_STATUS but got "
                                                      + SftpConstants.getCommandMessageName(response.getType()));
        }
        return parse(response.getBuffer());
    }
}
