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

package org.apache.sshd.client.auth.hostbased;

import java.util.List;

import org.apache.sshd.client.auth.AbstractUserAuthFactory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactoriesManager;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthHostBasedFactory extends AbstractUserAuthFactory implements SignatureFactoriesManager {
    public static final String NAME = HOST_BASED;

    private List<NamedFactory<Signature>> factories;
    private HostKeyIdentityProvider clientHostKeys;
    private String clientUsername;
    private String clientHostname;

    public UserAuthHostBasedFactory() {
        super(NAME);
    }

    @Override
    public List<NamedFactory<Signature>> getSignatureFactories() {
        return factories;
    }

    @Override
    public void setSignatureFactories(List<NamedFactory<Signature>> factories) {
        this.factories = factories;
    }

    public HostKeyIdentityProvider getClientHostKeys() {
        return clientHostKeys;
    }

    public void setClientHostKeys(HostKeyIdentityProvider clientHostKeys) {
        this.clientHostKeys = clientHostKeys;
    }

    public String getClientUsername() {
        return clientUsername;
    }

    public void setClientUsername(String clientUsername) {
        this.clientUsername = clientUsername;
    }

    public String getClientHostname() {
        return clientHostname;
    }

    public void setClientHostname(String clientHostname) {
        this.clientHostname = clientHostname;
    }

    @Override
    public UserAuthHostBased create() {
        UserAuthHostBased auth = new UserAuthHostBased(getClientHostKeys());
        auth.setClientHostname(getClientHostname());
        auth.setClientUsername(getClientUsername());
        auth.setSignatureFactories(getSignatureFactories());
        return auth;
    }
}
