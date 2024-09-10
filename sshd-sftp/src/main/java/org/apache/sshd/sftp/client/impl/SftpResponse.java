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

import java.io.IOException;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.sftp.common.SftpConstants;

/**
 * A representation of an SFTP response to a request.
 */
public final class SftpResponse {

    private final int cmd;

    private final int id;

    private final int type;

    private final int length;

    private final Buffer buffer;

    private SftpResponse(int cmd, int id, int type, int length, Buffer buffer) {
        this.cmd = cmd;
        this.id = id;
        this.type = type;
        this.length = length;
        this.buffer = buffer;
    }

    public int getCmd() {
        return cmd;
    }

    public int getId() {
        return id;
    }

    public int getType() {
        return type;
    }

    public int getLength() {
        return length;
    }

    public Buffer getBuffer() {
        return buffer;
    }

    public static SftpResponse parse(int cmd, Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        // No need to validate the length here: the way we assemble these buffers guarantees that
        // the length is reasonable and does not exceed buffer.available().
        return new SftpResponse(cmd, id, type, length, buffer);
    }

    public static void validateIncomingResponse(int cmd, int id, int type, int length, Buffer buffer) throws IOException {
        int remaining = buffer.available();
        if ((length < 0) || (length > (remaining + 5 /* type + id */))) {
            throw new SshException("Bad length (" + length + ") for remaining data (" + remaining + ")" + " in response to "
                                   + SftpConstants.getCommandMessageName(cmd) + ": type="
                                   + SftpConstants.getCommandMessageName(type) + ", id=" + id);
        }
    }
}
