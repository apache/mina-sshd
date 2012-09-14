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

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.ForwardingAcceptorFactory;
import org.apache.sshd.server.auth.gss.GSSAuthenticator;

/**
 * The <code>ServerFactoryManager</code> enable the retrieval of additional
 * configuration needed specifically for the server side.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ServerFactoryManager extends FactoryManager {
    /**
     * Key used to retrieve the value of the maximum concurrent open session count per username
     */
    public static final String MAX_CONCURRENT_SESSIONS = "max-concurrent-sessions";
    /**
     * Key used to retrieve the value of the server identification string if not default.
     */
    public static final String SERVER_IDENTIFICATION = "server-identification";
    /**
     * Key used to retrieve the value in the configuration properties map
     * of the maximum number of failed authentication requests before the
     * server closes the connection.
     */
    public static final String MAX_AUTH_REQUESTS = "max-auth-requests";

    /**
     * Key used to retrieve the value of the timeout after which
     * the server will close the connection if the client has not been
     * authenticated.
     */
    public static final String AUTH_TIMEOUT = "auth-timeout";

    /**
     * Key used to retrieve the value of idle timeout after which
     * the server will close the connection.  In milliseconds.
     */
    public static final String IDLE_TIMEOUT = "idle-timeout";


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
     * Retrieve the <code>GSSAuthenticator</code> to be used by the SSH server.
     * If no authenticator has been configured (i.e. this method returns
     * <code>null</code>), then client authentication requests based on gssapi 
     * will be rejected.
     *
     * @return the <code>GSSAuthenticator</code> or <code>null</code>
     */
    GSSAuthenticator getGSSAuthenticator();

    /**
     * Retrieve the <code>ForwardingFilter</code> to be used by the SSH server.
     * If no filter has been configured (i.e. this method returns
     * <code>null</code>), then all forwarding requests will be rejected.
     *
     * @return the <code>ForwardingFilter</code> or <code>null</code>
     */
    ForwardingFilter getForwardingFilter();

    /**
     * Retrieve the <code>ShellFactory</code> object to be used to create shells.
     *
     * @return a valid <code>ShellFactory</code> object or <code>null</code> if shells
     *         are not supported on this server
     */
    Factory<Command> getShellFactory();

    /**
     * Retrieve the <code>CommandFactory</code> to be used to process commands requests.
     *
     * @return a valid <code>CommandFactory</code> object or <code>null</code> if commands
     *         are not supported on this server
     */
    CommandFactory getCommandFactory();

    /**
     * Retrieve the <code>FileSystemFactory</code> to be used to traverse the file system.
     *
     * @return a valid <code>FileSystemFactory</code> object or <code>null</code> if commands
     *         are not supported on this server
     */
    FileSystemFactory getFileSystemFactory();

    /**
     * Retrieve the list of named factories for <code>CommandFactory.Command</code> to
     * be used to create subsystems.
     *
     * @return a list of named <code>CommandFactory.Command</code> factories
     *         or <code>null</code> if subsystems are not supported on this server
     */
    List<NamedFactory<Command>> getSubsystemFactories();

    /**
     * Retrieve the IoAcceptor factory to be used to accept incoming connections
     * for X11 Forwards.
     * 
     * @return A <code>ForwardNioAcceptorFactory</code>
     */
    ForwardingAcceptorFactory getX11ForwardingAcceptorFactory();

}
