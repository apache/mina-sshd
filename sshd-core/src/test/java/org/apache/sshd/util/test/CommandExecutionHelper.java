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

package org.apache.sshd.util.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import org.apache.sshd.server.command.AbstractCommandSupport;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class CommandExecutionHelper extends AbstractCommandSupport {
    protected CommandExecutionHelper() {
        this(null);
    }

    protected CommandExecutionHelper(String command) {
        super(command, null);
    }

    @Override
    public void run() {
        String command = getCommand();
        try {
            if (command == null) {
                try (BufferedReader r = new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8))) {
                    for (;;) {
                        command = r.readLine();
                        if (command == null) {
                            return;
                        }

                        if (!handleCommandLine(command)) {
                            return;
                        }
                    }
                }
            } else {
                handleCommandLine(command);
            }
        } catch (InterruptedIOException e) {
            // Ignore - signaled end
        } catch (Exception e) {
            String message = "Failed (" + e.getClass().getSimpleName() + ") to handle '" + command + "': " + e.getMessage();
            try {
                OutputStream stderr = getErrorStream();
                stderr.write(message.getBytes(StandardCharsets.US_ASCII));
            } catch (IOException ioe) {
                log.warn("Failed ({}) to write error message={}: {}",
                        e.getClass().getSimpleName(), message, ioe.getMessage());
            } finally {
                onExit(-1, message);
            }
        } finally {
            onExit(0);
        }
    }

    /**
     * @param  command   The command line
     * @return           {@code true} if continue accepting command
     * @throws Exception If failed to handle the command line
     */
    protected abstract boolean handleCommandLine(String command) throws Exception;
}
