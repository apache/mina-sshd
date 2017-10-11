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

package org.apache.sshd.client.auth;

import java.util.Objects;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractUserAuth extends AbstractLoggingBean implements UserAuth {
    private final String name;
    private ClientSession clientSession;
    private String service;

    protected AbstractUserAuth(String name) {
        this.name = ValidateUtils.checkNotNullAndNotEmpty(name, "No name");
    }

    @Override
    public ClientSession getClientSession() {
        return clientSession;
    }

    @Override
    public ClientSession getSession() {
        return getClientSession();
    }

    @Override
    public final String getName() {
        return name;
    }

    public String getService() {
        return service;
    }

    @Override
    public void init(ClientSession session, String service) throws Exception {
        this.clientSession = Objects.requireNonNull(session, "No client session");
        this.service = ValidateUtils.checkNotNullAndNotEmpty(service, "No service");
    }

    @Override
    public boolean process(Buffer buffer) throws Exception {
        ClientSession session = getClientSession();
        String service = getService();
        if (buffer == null) {
            return sendAuthDataRequest(session, service);
        } else {
            return processAuthDataRequest(session, service, buffer);
        }
    }

    protected abstract boolean sendAuthDataRequest(ClientSession session, String service) throws Exception;

    protected abstract boolean processAuthDataRequest(ClientSession session, String service, Buffer buffer) throws Exception;

    @Override
    public void destroy() {
        if (log.isDebugEnabled()) {
            log.debug("destroy({})[{}]", getClientSession(), getService());
        }
    }

    @Override
    public String toString() {
        return getName() + ": " + getSession() + "[" + getService() + "]";
    }
}
