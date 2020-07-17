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

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.server.command.CommandFactory;
import org.apache.sshd.server.session.ServerProxyAcceptorHolder;
import org.apache.sshd.server.shell.ShellFactory;
import org.apache.sshd.server.subsystem.SubsystemFactory;

/**
 * The <code>ServerFactoryManager</code> enable the retrieval of additional configuration needed specifically for the
 * server side.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ServerFactoryManager
        extends FactoryManager,
        ServerProxyAcceptorHolder,
        ServerAuthenticationManager {

    /**
     * Retrieve the {@link ShellFactory} object to be used to create shells.
     *
     * @return a valid {@link ShellFactory} object or {@code null} if shells are not supported on this server
     */
    ShellFactory getShellFactory();

    /**
     * Retrieve the <code>CommandFactory</code> to be used to process commands requests.
     *
     * @return A valid {@link CommandFactory} object or {@code null} if commands are not supported on this server
     */
    CommandFactory getCommandFactory();

    /**
     * Retrieve the list of named factories for <code>CommandFactory.Command</code> to be used to create subsystems.
     *
     * @return a list of named {@link SubsystemFactory}-ies or {@code null}/empty if subsystems are not supported on
     *         this server
     */
    List<SubsystemFactory> getSubsystemFactories();
}
