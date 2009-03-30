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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

/**
 * This shell have inverted streams, such as the one obtained when launching a
 * new {@link Process} from java.  This interface is meant to be used with
 * {@link InvertedShellWrapper} class as an implementation of
 * {@link org.apache.sshd.server.ShellFactory.Shell}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public interface InvertedShell {

    /**
     * Starts the shell and will make the streams available for
     * the ssh server to retrieve and use.
     *
     * @param env
     * @throws Exception
     */
    void start(Map<String,String> env) throws IOException;

    /**
     * Returns the output stream used to feed the shell.
     * This method is called after the shell has been started.
     *
     * @return
     */
    OutputStream getInputStream();

    /**
     * Return an InputStream representing the output stream of the shell.
     * @return
     */
    InputStream getOutputStream();

    /**
     * Return an InputStream representing the error stream of the shell.
     * @return
     */
    InputStream getErrorStream();

    /**
     * Check if the underlying shell is still alive
     * @return
     */
    boolean isAlive();

    /**
     * Retrieve the exit value of the shell.
     * This method must only be called when the shell is not alive anymore.
     *
     * @return the exit value of the shell
     */
    int exitValue();

    /**
     * Destroy the shell.
     * This method can be called by the SSH server to destroy the shell because
     * the client has disconnected somehow.
     */
    void destroy();
}
