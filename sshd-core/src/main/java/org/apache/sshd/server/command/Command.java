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
package org.apache.sshd.server.command;

import java.io.InputStream;
import java.io.OutputStream;

import org.apache.sshd.server.ExitCallback;

/**
 * <p>
 * Represents a command, shell or subsystem that can be used to send command.
 * </p>
 *
 * <p>
 * This command have direct streams, meaning those streams will be provided by the ssh server for the shell to use
 * directly. This interface is suitable for implementing commands in java, rather than using external processes. For
 * wrapping such processes or using inverted streams,
 * </p>
 * see {@link org.apache.sshd.server.shell.InvertedShellWrapper}.
 */
public interface Command extends CommandLifecycle {

    /**
     * Set the input stream that can be used by the shell to read input.
     *
     * @param in The {@link InputStream} used by the shell to read input.
     */
    void setInputStream(InputStream in);

    /**
     * Set the output stream that can be used by the shell to write its output.
     *
     * @param out The {@link OutputStream} used by the shell to write its output
     */
    void setOutputStream(OutputStream out);

    /**
     * Set the error stream that can be used by the shell to write its errors.
     *
     * @param err The {@link OutputStream} used by the shell to write its errors
     */
    void setErrorStream(OutputStream err);

    /**
     * Set the callback that the shell has to call when it is closed.
     *
     * @param callback The {@link ExitCallback} to call when shell is closed
     */
    void setExitCallback(ExitCallback callback);
}
