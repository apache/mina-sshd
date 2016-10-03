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
package org.apache.sshd.deprecated;

import java.util.Objects;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionHolder;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 */
public abstract class AbstractUserAuth
        extends AbstractLoggingBean
        implements UserAuth, SessionHolder<ClientSession>, ClientSessionHolder {
    private final ClientSession session;
    private final String service;

    protected AbstractUserAuth(ClientSession session, String service) {
        this.session = Objects.requireNonNull(session, "No client session");
        this.service = service;
    }

    @Override
    public ClientSession getClientSession() {
        return session;
    }

    @Override
    public final ClientSession getSession() {
        return getClientSession();
    }

    public String getService() {
        return service;
    }
}
