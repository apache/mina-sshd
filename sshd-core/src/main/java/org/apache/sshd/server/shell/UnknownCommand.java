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
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;

/**
 * Implementation of an unknown command that can be returned by <code>CommandFactory</code> when the command is not
 * known, as it is supposed to always return a valid <code>Command</code> object.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UnknownCommand implements Command, Runnable {

    private final String command;
    private final String message;
    @SuppressWarnings("unused")
    private InputStream in;
    @SuppressWarnings("unused")
    private OutputStream out;
    private OutputStream err;
    private ExitCallback callback;

    public UnknownCommand(String command) {
        this.command = ValidateUtils.checkNotNullAndNotEmpty(command, "No command");
        this.message = "Unknown command: " + command;
    }

    public String getCommand() {
        return command;
    }

    public String getMessage() {
        return message;
    }

    @Override
    public void setInputStream(InputStream in) {
        this.in = in;
    }

    @Override
    public void setOutputStream(OutputStream out) {
        this.out = out;
    }

    @Override
    public void setErrorStream(OutputStream err) {
        this.err = err;
    }

    @Override
    public void setExitCallback(ExitCallback callback) {
        this.callback = callback;
    }

    @Override
    public void run() {
        String errorMessage = getMessage();
        try {
            try {
                err.write(errorMessage.getBytes(StandardCharsets.UTF_8));
                err.write('\n');
            } finally {
                err.flush();
            }
        } catch (IOException e) {
            // ignored
        }

        if (callback != null) {
            callback.onExit(1, errorMessage);
        }
    }

    @Override
    public void start(ChannelSession channel, Environment env) throws IOException {
        Thread thread = new Thread(this);
        thread.setDaemon(true);
        thread.start();
    }

    @Override
    public void destroy(ChannelSession channel) {
        // ignored
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getCommand());
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }

        return Objects.equals(this.getCommand(), ((UnknownCommand) obj).getCommand());
    }

    @Override
    public String toString() {
        return getMessage();
    }
}
