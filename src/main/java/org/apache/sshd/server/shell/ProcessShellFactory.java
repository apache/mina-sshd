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
package org.apache.sshd.server.shell;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.util.Map;

import org.apache.sshd.server.ShellFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link ShellFactory} that will create a new process and bridge
 * the streams.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public class ProcessShellFactory implements ShellFactory {

    private static final Logger LOG = LoggerFactory.getLogger(ProcessShellFactory.class);

    private String[] command;

    public ProcessShellFactory() {
    }

    public ProcessShellFactory(String[] command) {
        this.command = command;
    }

    public String[] getCommand() {
        return command;
    }

    public void setCommand(String[] command) {
        this.command = command;
    }

    public Shell createShell() {
        return new InvertedShellWrapper(new ProcessShell(command));
    }

    public static class ProcessShell implements InvertedShell {

        private String[] command;
        private Process process;

        public ProcessShell(String[] command) {
            this.command = command;
        }

        public void start(Map<String,String> env) throws IOException {
            String[] cmds = new String[command.length];
            for (int i = 0; i < cmds.length; i++) {
                if ("$USER".equals(command[i])) {
                    cmds[i] = env.get("USER");
                } else {
                    cmds[i] = command[i];
                }
            }
            ProcessBuilder builder = new ProcessBuilder(cmds);
            if (env != null) {
                builder.environment().putAll(env);
            }
            LOG.info("Starting shell with command: '{}' and env: {}", builder.command(), builder.environment());
            process = builder.start();
        }

        public OutputStream getInputStream() {
            return process.getOutputStream();
        }

        public InputStream getOutputStream() {
            return process.getInputStream();
        }

        public InputStream getErrorStream() {
            return process.getErrorStream();
        }

        public boolean isAlive() {
            try {
                process.exitValue();
                return false;
            } catch (IllegalThreadStateException e) {
                return true;
            }
        }

        public int exitValue() {
            return process.exitValue();
        }

        public void destroy() {
            process.destroy();
        }
    }

}
