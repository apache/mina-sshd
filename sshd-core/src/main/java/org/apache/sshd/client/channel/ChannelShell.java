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
package org.apache.sshd.client.channel;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.sshd.common.PtyMode;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.SttySupport;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelShell extends ChannelSession {

    private boolean agentForwarding;
    private boolean usePty = true;
    private String ptyType;
    private int ptyColumns;
    private int ptyLines;
    private int ptyWidth;
    private int ptyHeight;
    private Map<PtyMode, Integer> ptyModes;
    private Map<String, String> env = new LinkedHashMap<String, String>();

    public ChannelShell() {
        ptyType = System.getenv("TERM");
        if (ptyType == null) {
            ptyType = "dummy";
        }
        ptyColumns = 80;
        ptyLines = 24;
        ptyWidth = 640;
        ptyHeight = 480;
        // Set up default pty modes
        ptyModes = new HashMap<PtyMode, Integer>();
        ptyModes.put(PtyMode.ISIG, 1);
        ptyModes.put(PtyMode.ICANON, 1);
        ptyModes.put(PtyMode.ECHO, 1);
        ptyModes.put(PtyMode.ECHOE, 1);
        ptyModes.put(PtyMode.ECHOK, 1);
        ptyModes.put(PtyMode.ECHONL, 0);
        ptyModes.put(PtyMode.NOFLSH, 0);
    }

    public void setupSensibleDefaultPty() {
        try {
            if (OsUtils.isUNIX()) {
                ptyModes = SttySupport.getUnixPtyModes();
                ptyColumns = SttySupport.getTerminalWidth();
                ptyLines = SttySupport.getTerminalHeight();
            } else {
                ptyType = "windows";
            }
        } catch (Throwable t) {
            // Ignore exceptions
        }
    }

    public boolean isAgentForwarding() {
        return agentForwarding;
    }

    public void setAgentForwarding(boolean agentForwarding) {
        this.agentForwarding = agentForwarding;
    }

    public boolean isUsePty() {
        return usePty;
    }

    public void setUsePty(boolean usePty) {
        this.usePty = usePty;
    }

    public String getPtyType() {
        return ptyType;
    }

    public void setPtyType(String ptyType) {
        this.ptyType = ptyType;
    }

    public int getPtyColumns() {
        return ptyColumns;
    }

    public void setPtyColumns(int ptyColumns) {
        this.ptyColumns = ptyColumns;
    }

    public int getPtyLines() {
        return ptyLines;
    }

    public void setPtyLines(int ptyLines) {
        this.ptyLines = ptyLines;
    }

    public int getPtyWidth() {
        return ptyWidth;
    }

    public void setPtyWidth(int ptyWidth) {
        this.ptyWidth = ptyWidth;
    }

    public int getPtyHeight() {
        return ptyHeight;
    }

    public void setPtyHeight(int ptyHeight) {
        this.ptyHeight = ptyHeight;
    }

    public Map<PtyMode, Integer> getPtyModes() {
        return ptyModes;
    }

    public void setPtyModes(Map<PtyMode, Integer> ptyModes) {
        this.ptyModes = ptyModes;
    }

    public void setEnv(String key, String value) {
        env.put(key, value);
    }

    protected void doOpen() throws Exception {
        super.doOpen();

        Buffer buffer;

        if (agentForwarding) {
            log.info("Send agent forwarding request");
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_REQUEST, 0);
            buffer.putInt(recipient);
            buffer.putString("auth-agent-req@openssh.com");
            buffer.putBoolean(false);
            session.writePacket(buffer);
        }

        if (usePty) {
            log.info("Send SSH_MSG_CHANNEL_REQUEST pty-req");
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_REQUEST, 0);
            buffer.putInt(recipient);
            buffer.putString("pty-req");
            buffer.putBoolean(false);
            buffer.putString(ptyType);
            buffer.putInt(ptyColumns);
            buffer.putInt(ptyLines);
            buffer.putInt(ptyHeight);
            buffer.putInt(ptyWidth);
            Buffer modes = new Buffer();
            for (PtyMode mode : ptyModes.keySet()) {
                modes.putByte((byte) mode.toInt());
                modes.putInt(ptyModes.get(mode));
            }
            modes.putByte((byte) 0);
            buffer.putBytes(modes.getCompactData());
            session.writePacket(buffer);
        }

        if (!env.isEmpty()) {
            log.info("Send SSH_MSG_CHANNEL_REQUEST env");
            for (Map.Entry<String, String> entry : env.entrySet()) {
                buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_REQUEST, 0);
                buffer.putInt(recipient);
                buffer.putString("env");
                buffer.putBoolean(false);
                buffer.putString(entry.getKey());
                buffer.putString(entry.getValue());
                session.writePacket(buffer);
            }
        }

        log.info("Send SSH_MSG_CHANNEL_REQUEST shell");
        buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_REQUEST, 0);
        buffer.putInt(recipient);
        buffer.putString("shell");
        buffer.putBoolean(false);
        session.writePacket(buffer);

    }

}
