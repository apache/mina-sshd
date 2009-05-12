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

import java.util.List;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;

/**
 * The <code>ServerFactoryManager</code> enable the retrieval of additional
 * configuration needed specifically for the server side.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ServerFactoryManager extends FactoryManager {

    /**
     * Retrieve the list of named factories for <code>UserAuth<code> objects.
     *
     * @return a list of named <code>UserAuth</code> factories, never <code>null</code>
     */
    List<NamedFactory<UserAuth>> getUserAuthFactories();

    /**
     * Retrieve the <code>PublickeyAuthenticator</code> to be used by SSH server.
     * If no authenticator has been configured (i.e. this method returns
     * <code>null</code>), then client authentication requests based on keys will be
     * rejected.
     *
     * @return the <code>PublickeyAuthenticato</code> or <code>null</code>
     */
    PublickeyAuthenticator getPublickeyAuthenticator();

    /**
     * Retrieve the <code>PasswordAuthenticator</code> to be used by the SSH server.
     * If no authenticator has been configured (i.e. this method returns
     * <code>null</code>), then client authentication requests based on passwords
     * will be rejected.
     *
     * @return the <code>PasswordAuthenticator</code> or <code>null</code>
     */
    PasswordAuthenticator getPasswordAuthenticator();

    /**
     * Retrieve the list of named factories for <code>ServerChannel</code> objects.
     *
     * @return a list of named <code>ServerChannel</code> factories, never <code>null</code>
     */
    List<NamedFactory<ServerChannel>> getChannelFactories();

    /**
     * Retrieve the <code>ShellFactory</code> object to be used to create shells.
     *
     * @return a valid <code>ShellFactory</code> object or <code>null</code> if shells
     *         are not supported on this server
     */
    ShellFactory getShellFactory();

    /**
     * Retrieve the <code>CommandFactory</code> to be used to process commands requests.
     *
     * @return a valid <code>CommandFactory</code> object or <code>null</code> if commands
     *         are not supported on this server
     */
    CommandFactory getCommandFactory();

}
