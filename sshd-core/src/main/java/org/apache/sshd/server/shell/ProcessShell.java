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
package org.apache.sshd.server.shell;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.channel.PtyMode;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.channel.PuttyRequestHandler;
import org.apache.sshd.server.session.ServerSession;

/**
 * Bridges the I/O streams between the SSH command and the process that executes it
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ProcessShell extends AbstractLoggingBean implements InvertedShell {
    private final List<String> command;
    private String cmdValue;
    private ServerSession session;
    private ChannelSession channel;
    private Process process;
    private TtyFilterOutputStream in;
    private TtyFilterInputStream out;
    private TtyFilterInputStream err;

    /**
     * @param command The command components which when joined (with space separator) create the full command to be
     *                executed by the shell
     */
    public ProcessShell(String... command) {
        this(GenericUtils.isEmpty(command) ? Collections.emptyList() : Arrays.asList(command));
    }

    public ProcessShell(Collection<String> command) {
        // we copy the original list so as not to change it
        this.command = new ArrayList<>(
                ValidateUtils.checkNotNullAndNotEmpty(command, "No process shell command(s)"));
        this.cmdValue = GenericUtils.join(command, ' ');
    }

    @Override
    public ServerSession getServerSession() {
        return session;
    }

    @Override
    public void setSession(ServerSession session) {
        this.session = Objects.requireNonNull(session, "No server session");
        ValidateUtils.checkTrue(process == null, "Session set after process started");
    }

    @Override
    public ChannelSession getChannelSession() {
        return channel;
    }

    @Override
    public void start(ChannelSession channel, Environment env) throws IOException {
        this.channel = channel;

        Map<String, String> varsMap = resolveShellEnvironment(env.getEnv());
        for (int i = 0; i < command.size(); i++) {
            String cmd = command.get(i);
            if ("$USER".equals(cmd)) {
                cmd = varsMap.get("USER");
                command.set(i, cmd);
                cmdValue = GenericUtils.join(command, ' ');
            }
        }

        ProcessBuilder builder = new ProcessBuilder(command);
        if (GenericUtils.size(varsMap) > 0) {
            try {
                Map<String, String> procEnv = builder.environment();
                procEnv.putAll(varsMap);
            } catch (Exception e) {
                warn("start({}) - Failed ({}) to set environment for command={}: {}",
                        channel, e.getClass().getSimpleName(), cmdValue, e.getMessage(), e);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("start({}): command='{}', env={}",
                    channel, builder.command(), builder.environment());
        }

        process = builder.start();

        Map<PtyMode, ?> modes = resolveShellTtyOptions(env.getPtyModes());
        out = new TtyFilterInputStream(process.getInputStream(), modes);
        err = new TtyFilterInputStream(process.getErrorStream(), modes);
        in = new TtyFilterOutputStream(process.getOutputStream(), err, modes);
    }

    protected Map<String, String> resolveShellEnvironment(Map<String, String> env) {
        return env;
    }

    // for some reason these modes provide best results BOTH with Linux SSH client and PUTTY
    protected Map<PtyMode, Integer> resolveShellTtyOptions(Map<PtyMode, Integer> modes) {
        if (PuttyRequestHandler.isPuttyClient(getServerSession())) {
            return PuttyRequestHandler.resolveShellTtyOptions(modes);
        } else {
            return modes;
        }
    }

    @Override
    public OutputStream getInputStream() {
        return in;
    }

    @Override
    public InputStream getOutputStream() {
        return out;
    }

    @Override
    public InputStream getErrorStream() {
        return err;
    }

    @Override
    public boolean isAlive() {
        return process.isAlive();
    }

    @Override
    public int exitValue() {
        if (isAlive()) {
            try {
                return process.waitFor();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        } else {
            return process.exitValue();
        }
    }

    @Override
    public void destroy(ChannelSession channel) {
        // NOTE !!! DO NOT NULL-IFY THE PROCESS SINCE "exitValue" is called subsequently
        boolean debugEnabled = log.isDebugEnabled();
        if (process != null) {
            if (debugEnabled) {
                log.debug("destroy({}) Destroy process for '{}'", channel, cmdValue);
            }
            process.destroy();
        }

        IOException e = IoUtils.closeQuietly(getInputStream(), getOutputStream(), getErrorStream());
        if (e != null) {
            debug("destroy({}) {} while destroy streams of '{}': {}",
                    channel, e.getClass().getSimpleName(), this, e.getMessage(), e);
        }
    }

    @Override
    public String toString() {
        return GenericUtils.isEmpty(cmdValue) ? super.toString() : cmdValue;
    }
}
