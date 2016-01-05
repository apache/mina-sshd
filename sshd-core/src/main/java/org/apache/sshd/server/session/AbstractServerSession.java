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

package org.apache.sshd.server.session;

import java.util.List;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.auth.UserAuth;
import org.apache.sshd.server.auth.gss.GSSAuthenticator;
import org.apache.sshd.server.auth.hostbased.HostBasedAuthenticator;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractServerSession extends AbstractSession implements ServerSession {
    private PasswordAuthenticator passwordAuthenticator;
    private PublickeyAuthenticator publickeyAuthenticator;
    private KeyboardInteractiveAuthenticator interactiveAuthenticator;
    private GSSAuthenticator gssAuthenticator;
    private HostBasedAuthenticator hostBasedAuthenticator;
    private List<NamedFactory<UserAuth>> userAuthFactories;

    protected AbstractServerSession(ServerFactoryManager factoryManager, IoSession ioSession) {
        super(true, factoryManager, ioSession);
    }

    @Override
    public ServerFactoryManager getFactoryManager() {
        return (ServerFactoryManager) super.getFactoryManager();
    }

    @Override
    public PasswordAuthenticator getPasswordAuthenticator() {
        return resolveEffectiveProvider(PasswordAuthenticator.class, passwordAuthenticator, getFactoryManager().getPasswordAuthenticator());
    }

    @Override
    public void setPasswordAuthenticator(PasswordAuthenticator passwordAuthenticator) {
        this.passwordAuthenticator = passwordAuthenticator; // OK if null - inherit from parent
    }

    @Override
    public PublickeyAuthenticator getPublickeyAuthenticator() {
        return resolveEffectiveProvider(PublickeyAuthenticator.class, publickeyAuthenticator, getFactoryManager().getPublickeyAuthenticator());
    }

    @Override
    public void setPublickeyAuthenticator(PublickeyAuthenticator publickeyAuthenticator) {
        this.publickeyAuthenticator = publickeyAuthenticator; // OK if null - inherit from parent
    }

    @Override
    public KeyboardInteractiveAuthenticator getKeyboardInteractiveAuthenticator() {
        return resolveEffectiveProvider(KeyboardInteractiveAuthenticator.class, interactiveAuthenticator, getFactoryManager().getKeyboardInteractiveAuthenticator());
    }

    @Override
    public void setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator interactiveAuthenticator) {
        this.interactiveAuthenticator = interactiveAuthenticator; // OK if null - inherit from parent
    }

    @Override
    public GSSAuthenticator getGSSAuthenticator() {
        return resolveEffectiveProvider(GSSAuthenticator.class, gssAuthenticator, getFactoryManager().getGSSAuthenticator());
    }

    @Override
    public void setGSSAuthenticator(GSSAuthenticator gssAuthenticator) {
        this.gssAuthenticator = gssAuthenticator; // OK if null - inherit from parent
    }

    @Override
    public HostBasedAuthenticator getHostBasedAuthenticator() {
        return resolveEffectiveProvider(HostBasedAuthenticator.class, hostBasedAuthenticator, getFactoryManager().getHostBasedAuthenticator());
    }

    @Override
    public void setHostBasedAuthenticator(HostBasedAuthenticator hostBasedAuthenticator) {
        this.hostBasedAuthenticator = hostBasedAuthenticator;
    }

    @Override
    public List<NamedFactory<UserAuth>> getUserAuthFactories() {
        return resolveEffectiveFactories(UserAuth.class, userAuthFactories, getFactoryManager().getUserAuthFactories());
    }

    @Override
    public void setUserAuthFactories(List<NamedFactory<UserAuth>> userAuthFactories) {
        this.userAuthFactories = userAuthFactories; // OK if null/empty - inherit from parent
    }

    @Override
    protected void checkKeys() {
        // nothing
    }
}
