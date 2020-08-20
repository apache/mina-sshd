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
package org.apache.sshd.client;

import org.apache.sshd.client.config.hosts.HostConfigEntryResolver;
import org.apache.sshd.client.config.keys.ClientIdentityLoaderManager;
import org.apache.sshd.client.session.ClientProxyConnectorHolder;
import org.apache.sshd.client.session.ClientSessionCreator;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.config.keys.FilePasswordProviderManager;

/**
 * The <code>ClientFactoryManager</code> enable the retrieval of additional configuration needed specifically for the
 * client side.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ClientFactoryManager
        extends FactoryManager,
        ClientSessionCreator,
        ClientProxyConnectorHolder,
        FilePasswordProviderManager,
        ClientIdentityLoaderManager,
        ClientAuthenticationManager {

    /**
     * @return The {@link HostConfigEntryResolver} to use in order to resolve the effective session parameters - never
     *         {@code null}
     */
    HostConfigEntryResolver getHostConfigEntryResolver();

    void setHostConfigEntryResolver(HostConfigEntryResolver resolver);
}
