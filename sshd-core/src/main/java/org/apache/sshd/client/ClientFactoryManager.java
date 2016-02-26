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
import org.apache.sshd.client.config.keys.ClientIdentityLoader;
import org.apache.sshd.client.session.ClientProxyConnectorHolder;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.scp.ScpFileOpenerHolder;

/**
 * The <code>ClientFactoryManager</code> enable the retrieval of additional
 * configuration needed specifically for the client side.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ClientFactoryManager
        extends FactoryManager,
                ScpFileOpenerHolder,
                ClientProxyConnectorHolder,
                ClientAuthenticationManager {

    /**
     * Key used to retrieve the value of the client identification string.
     * If set, then it is <U>appended</U> to the (standard) &quot;SSH-2.0-&quot;
     * prefix. Otherwise a default is sent that consists of &quot;SSH-2.0-&quot;
     * plus the current SSHD core artifact name and version in uppercase - e.g.,
     * &quot;SSH-2.0-SSHD-CORE-1.0.0&quot;
     */
    String CLIENT_IDENTIFICATION = "client-identification";

    /**
     * Key used to set the heartbeat interval in milliseconds (0 to disable = default)
     */
    String HEARTBEAT_INTERVAL = "hearbeat-interval";

    /**
     * Default value for {@link #HEARTBEAT_INTERVAL} if none configured
     */
    long DEFAULT_HEARTBEAT_INTERVAL = 0L;

    /**
     * Key used to check the heartbeat request that should be sent to the server
     */
    String HEARTBEAT_REQUEST = "heartbeat-request";

    /**
     * Default value for {@link ClientFactoryManager#HEARTBEAT_REQUEST} is none configured
     */
    String DEFAULT_KEEP_ALIVE_HEARTBEAT_STRING = "keepalive@sshd.apache.org";

    /**
     * Whether to ignore invalid identities files when pre-initializing
     * the client session
     * @see ClientIdentityLoader#isValidLocation(String)
     */
    String IGNORE_INVALID_IDENTITIES = "ignore-invalid-identities";

    /**
     * Default value of {@link #IGNORE_INVALID_IDENTITIES} if none configured
     */
    boolean DEFAULT_IGNORE_INVALID_IDENTITIES = true;

    /**
     * @return The {@link HostConfigEntryResolver} to use in order to resolve the
     * effective session parameters - never {@code null}
     */
    HostConfigEntryResolver getHostConfigEntryResolver();
    void setHostConfigEntryResolver(HostConfigEntryResolver resolver);

    /**
     * @return The {@link ClientIdentityLoader} to use in order to load client
     * key pair identities - never {@code null}
     */
    ClientIdentityLoader getClientIdentityLoader();
    void setClientIdentityLoader(ClientIdentityLoader loader);

    /**
     * @return The {@link FilePasswordProvider} to use if need to load encrypted
     * identities keys - never {@code null}
     * @see FilePasswordProvider#EMPTY
     */
    FilePasswordProvider getFilePasswordProvider();
    void setFilePasswordProvider(FilePasswordProvider provider);
}
