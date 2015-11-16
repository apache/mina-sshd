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
import java.util.Collection;
import java.util.Map;
import java.util.Set;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * Bridges the I/O streams between the SSH command and the process that executes it
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ProcessShell extends AbstractLoggingBean implements InvertedShell {
    private final Set<TtyOptions> ttyOptions;
    private final String[] command;
    private String cmdValue;
    private Process process;
    private TtyFilterOutputStream in;
    private TtyFilterInputStream out;
    private TtyFilterInputStream err;

    public ProcessShell(Collection<TtyOptions> ttyOptions, String ... command) {
        // we create a copy of the options so as to avoid concurrent modifications
        this.ttyOptions = GenericUtils.of(ttyOptions);
        // we clone the original array so as not to change it
        this.command = ValidateUtils.checkNotNullAndNotEmpty(command, "No process shell command(s)").clone();
        this.cmdValue = GenericUtils.join(command, ' ');
    }

    @Override
    public void start(Map<String, String> env) throws IOException {
        for (int i = 0; i < command.length; i++) {
            String cmd = command[i];
            if ("$USER".equals(cmd)) {
                cmd = env.get("USER");
                command[i] = cmd;
                cmdValue = GenericUtils.join(command, ' ');
            }
        }

        ProcessBuilder builder = new ProcessBuilder(command);
        if (GenericUtils.size(env) > 0) {
            try {
                Map<String, String> procEnv = builder.environment();
                procEnv.putAll(env);
            } catch (Exception e) {
                log.warn("Could not set environment for command=" + cmdValue, e);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Starting shell with command: '{}' and env: {}", builder.command(), builder.environment());
        }

        process = builder.start();
        out = new TtyFilterInputStream(process.getInputStream(), ttyOptions);
        err = new TtyFilterInputStream(process.getErrorStream(), ttyOptions);
        in = new TtyFilterOutputStream(process.getOutputStream(), err, ttyOptions);
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
        // TODO in JDK-8 call process.isAlive()
        try {
            process.exitValue();
            return false;
        } catch (IllegalThreadStateException e) {
            return true;
        }
    }

    @Override
    public int exitValue() {
        // TODO in JDK-8 call process.isAlive()
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
    public void destroy() {
        // NOTE !!! DO NOT NULL-IFY THE PROCESS SINCE "exitValue" is called subsequently
        if (process != null) {
            log.debug("Destroy process for " + cmdValue);
            process.destroy();
        }

        IOException e = IoUtils.closeQuietly(getInputStream(), getOutputStream(), getErrorStream());
        if (e != null) {
            if (log.isDebugEnabled()) {
                log.debug(e.getClass().getSimpleName() + " while destroy streams of '" + cmdValue + "': " + e.getMessage());
            }
        }
    }

    @Override
    public String toString() {
        return GenericUtils.isEmpty(cmdValue) ? super.toString() : cmdValue;
    }
}