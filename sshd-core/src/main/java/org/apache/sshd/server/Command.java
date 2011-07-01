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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Represents a command, shell or subsystem that can be used to send command.
 *
 * This command have direct streams, meaning those streams will be provided by the ssh server
 * for the shell to use directy. This interface is suitable for implementing commands in java,
 * rather than using external processes.  For wrapping such processes or using inverted streams,
 * see {@link org.apache.sshd.server.shell.InvertedShellWrapper}.
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
     * @param callback
     */
    void setExitCallback(ExitCallback callback);

    /**
     * Starts the shell.
     * All streams must have been set before calling this method.
     * The command should implement Runnable, and this method
     * should spawn a new thread like:
     * <pre>
     * {@code
     * Thread(this).start();
     * }
     * </pre>
     *
     * @param env
     * @throws java.io.IOException
     */
    void start(Environment env) throws IOException;

    /**
     * Destroy the shell.
     * This method can be called by the SSH server to destroy the shell because
     * the client has disconnected somehow.
     */
    void destroy();

}
