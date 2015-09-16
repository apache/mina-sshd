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

import java.util.Collection;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionHolder;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractUserAuth
                extends AbstractLoggingBean
                implements UserAuth, ClientSessionHolder {
    private ClientSession session;
    private String service;

    protected AbstractUserAuth() {
        super();
    }

    @Override
    public ClientSession getClientSession() {
        return session;
    }

    public String getService() {
        return service;
    }

    @Override
    public void init(ClientSession session, String service, Collection<?> identities) throws Exception {
        this.session = ValidateUtils.checkNotNull(session, "No client session");
        this.service = service;
    }
}
