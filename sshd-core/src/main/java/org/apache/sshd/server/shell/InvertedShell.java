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

import java.io.InputStream;
import java.io.OutputStream;

import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.server.SessionAware;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.CommandLifecycle;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.ServerSessionHolder;

/**
 * This shell have inverted streams, such as the one obtained when launching a new {@link Process} from java. This
 * interface is meant to be used with {@link InvertedShellWrapper} class as an implementation of
 * {@link org.apache.sshd.common.Factory}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface InvertedShell
        extends SessionHolder<ServerSession>,
        ServerSessionHolder,
        CommandLifecycle,
        SessionAware {

    @Override
    default ServerSession getSession() {
        return getServerSession();
    }

    /**
     * @return The {@link ChannelSession} instance through which the shell was created - may be {@code null} if shell
     *         not started yet
     */
    ChannelSession getChannelSession();

    /**
     * Returns the output stream used to feed the shell. This method is called after the shell has been started.
     *
     * @return The {@link OutputStream} used to feed the shell
     */
    OutputStream getInputStream();

    /**
     * @return The {@link InputStream} representing the output stream of the shell
     */
    InputStream getOutputStream();

    /**
     * @return The {@link InputStream} representing the error stream of the shell
     */
    InputStream getErrorStream();

    /**
     * Check if the underlying shell is still alive
     *
     * @return {@code true} if alive
     */
    boolean isAlive();

    /**
     * Retrieve the exit value of the shell. This method must only be called when the shell is not alive anymore.
     *
     * @return the exit value of the shell
     */
    int exitValue();
}
