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

package org.apache.sshd.scp.common.helpers;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.scp.common.ScpException;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpAckInfo {
    // ACK status codes
    public static final int OK = 0;
    public static final int WARNING = 1;
    public static final int ERROR = 2;

    public static final ScpAckInfo OK_ACK_INFO = new ScpAckInfo(OK, null);

    private final int statusCode;
    private final String line;

    public ScpAckInfo(int statusCode) {
        this(statusCode, null);
    }

    public ScpAckInfo(int statusCode, String line) {
        ValidateUtils.checkTrue(statusCode >= 0, "Invalid status code: %d", statusCode);

        this.statusCode = statusCode;
        this.line = line;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getLine() {
        return line;
    }

    public <O extends OutputStream> O send(O out, Charset cs) throws IOException {
        return sendAck(out, cs, getStatusCode(), getLine());
    }

    public void validateCommandStatusCode(String command, Object location) throws IOException {
        int code = getStatusCode();
        if ((code != OK) && (code != WARNING)) {
            throw new ScpException(
                    "Bad reply code (" + code + ") for command='" + command + "' at " + location + ": " + getLine(), code);
        }
    }

    @Override
    public String toString() {
        int code = getStatusCode();
        String l = getLine();
        // OK code has no line
        if (code == OK) {
            return Integer.toString(code);
        } else if ((code == WARNING) || (code == ERROR)) {
            return GenericUtils.isEmpty(l) ? Integer.toString(code) : code + ": " + l;
        } else {
            return l;
        }
    }

    public static ScpAckInfo readAck(InputStream in, Charset cs, boolean canEof) throws IOException {
        int statusCode = in.read();
        if (statusCode == -1) {
            if (canEof) {
                return null;
            }
            throw new EOFException("readAck - EOF before ACK");
        }

        if (statusCode == OK) {
            return OK_ACK_INFO;  // OK status has no extra data
        }

        String line = ScpIoUtils.readLine(in, cs);
        return new ScpAckInfo(statusCode, line);
    }

    /**
     * Sends {@link #OK} ACK code
     *
     * @param  out         The target {@link OutputStream}
     * @param  cs          The {@link Charset} to use to write the textual data
     * @throws IOException If failed to send the ACK code
     */
    public static void sendOk(OutputStream out, Charset cs) throws IOException {
        sendAck(out, cs, OK, null /* ignored */);
    }

    public static <O extends OutputStream> O sendWarning(O out, Charset cs, String message) throws IOException {
        return sendAck(out, cs, ScpAckInfo.WARNING, (message == null) ? "" : message);
    }

    public static <O extends OutputStream> O sendError(O out, Charset cs, String message) throws IOException {
        return sendAck(out, cs, ScpAckInfo.ERROR, (message == null) ? "" : message);
    }

    public static <O extends OutputStream> O sendAck(
            O out, Charset cs, int level, String message)
            throws IOException {
        out.write(level);
        if (level != OK) {
            ScpIoUtils.writeLine(out, cs, message); // this also flushes
        } else {
            out.flush();
        }
        return out;
    }
}
