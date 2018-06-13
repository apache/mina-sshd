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
package org.apache.sshd.server;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.command.CommandFactory;
import org.apache.sshd.server.session.ServerProxyAcceptorHolder;

/**
 * The <code>ServerFactoryManager</code> enable the retrieval of additional
 * configuration needed specifically for the server side.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ServerFactoryManager
        extends FactoryManager,
                ServerProxyAcceptorHolder,
                ServerAuthenticationManager {

    /**
     * Key used to retrieve the value of the maximum concurrent open session count per username.
     * If not set, then unlimited
     */
    String MAX_CONCURRENT_SESSIONS = "max-concurrent-sessions";

    /**
     * Key used to retrieve any extra lines to be sent during
     * initial protocol handshake <U>before</U> the identification.
     * The configured string value should use {@value #SERVER_EXTRA_IDENT_LINES_SEPARATOR}
     * character to denote line breaks
     */
    String SERVER_EXTRA_IDENTIFICATION_LINES = "server-extra-identification-lines";

    /**
     * Separator used in the {@value #SERVER_EXTRA_IDENTIFICATION_LINES} configuration
     * string to indicate new line break
     */
    char SERVER_EXTRA_IDENT_LINES_SEPARATOR = '|';

    /**
     * Key used to retrieve the value of the server identification string.
     * If set, then it is <U>appended</U> to the (standard) &quot;SSH-2.0-&quot;
     * prefix. Otherwise a default is sent that consists of &quot;SSH-2.0-&quot;
     * plus the current SSHD core artifact name and version in uppercase - e.g.,
     * &quot;SSH-2.0-SSHD-CORE-1.0.0&quot;
     */
    String SERVER_IDENTIFICATION = "server-identification";

    /**
     * Key used to configure the timeout used when receiving a close request
     * on a channel to wait until the command cleanly exits after setting
     * an EOF on the input stream. In milliseconds.
     * @see #DEFAULT_COMMAND_EXIT_TIMEOUT
     */
    String COMMAND_EXIT_TIMEOUT = "command-exit-timeout";

    /**
     * Default {@value #COMMAND_EXIT_TIMEOUT} if not set
     */
    long DEFAULT_COMMAND_EXIT_TIMEOUT = TimeUnit.SECONDS.toMillis(5L);

    /**
     * A URL pointing to the moduli file.
     * If not specified, the default internal file will be used.
     */
    String MODULI_URL = "moduli-url";

    /**
     * Retrieve the <code>ShellFactory</code> object to be used to create shells.
     *
     * @return a valid <code>ShellFactory</code> object or {@code null} if shells
     * are not supported on this server
     */
    Factory<Command> getShellFactory();

    /**
     * Retrieve the <code>CommandFactory</code> to be used to process commands requests.
     *
     * @return A valid {@link CommandFactory} object or {@code null} if commands
     * are not supported on this server
     */
    CommandFactory getCommandFactory();

    /**
     * Retrieve the list of named factories for <code>CommandFactory.Command</code> to
     * be used to create subsystems.
     *
     * @return a list of named <code>CommandFactory.Command</code> factories
     * or {@code null} if subsystems are not supported on this server
     */
    List<NamedFactory<Command>> getSubsystemFactories();
}
