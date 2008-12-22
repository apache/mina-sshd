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
package org.apache.sshd.server;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

import org.apache.sshd.server.session.ServerSession;

/**
 * A factory of commands.
 * Commands are executed on the server side when an "exec" channel is
 * requested by the SSH client.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public interface CommandFactory {

    /**
     * Create a command with the given name.
     * If the command is not known, a dummy command should be returned to allow
     * the display output to be sent back to the client.
     *
     * @param command
     * @return a non null command
     */
    Command createCommand(String command);

    /**
     * Interface that can be implemented by a command to be able to access the
     * server session in which this command will be used.
     */
    public interface SessionAware {

        /**
         * Set the server session in which this command will be executed.
         *
         * @param session
         */
        void setSession(ServerSession session);
    }

    /**
     * A command that can be executed on the server side
     */
    public interface Command {

        /**
         * Set the input stream that can be used by the shell to read input.
         * @param in
         */
        void setInputStream(InputStream in);

        /**
         * Set the output stream that can be used by the shell to write its output.
         * @param out
         */
        void setOutputStream(OutputStream out);

        /**
         * Set the error stream that can be used by the shell to write its errors.
         * @param err
         */
        void setErrorStream(OutputStream err);

        /**
         * Set the callback that the shell has to call when it is closed.
         */
        void setExitCallback(ExitCallback callback);

        /**
         * Execute the command and return its status
         *
         * @return
         * @throws java.io.IOException
         */
        void start() throws IOException;
    }


    /**
     * Callback used by a command to notify the SSH server is has exited
     */
    public interface ExitCallback {

        /**
         * Informs the SSH server that the shell has exited
         *
         * @param exitValue the exit value
         */
        void onExit(int exitValue);

    }

}
