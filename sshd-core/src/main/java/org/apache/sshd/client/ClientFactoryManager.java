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
import org.apache.sshd.client.config.keys.ClientIdentityLoaderManager;
import org.apache.sshd.client.session.ClientProxyConnectorHolder;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.config.keys.FilePasswordProviderManager;

/**
 * The <code>ClientFactoryManager</code> enable the retrieval of additional
 * configuration needed specifically for the client side.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ClientFactoryManager
        extends FactoryManager,
                ClientProxyConnectorHolder,
                FilePasswordProviderManager,
                ClientIdentityLoaderManager,
                ClientAuthenticationManager {

    /**
     * Key used to retrieve the value of the client identification string.
     * If set, then it is <U>appended</U> to the (standard) &quot;SSH-2.0-&quot;
     * prefix. Otherwise a default is sent that consists of &quot;SSH-2.0-&quot;
     * plus the current SSHD artifact name and version in uppercase - e.g.,
     * &quot;SSH-2.0-APACHE-SSHD-1.0.0&quot;
     */
    String CLIENT_IDENTIFICATION = "client-identification";

    /**
     * Whether to send the identification string immediately upon session connection
     * being established or wait for the server's identification before sending our own.
     *
     * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-4.2">RFC 4253 - section 4.2 - Protocol Version Exchange</A>
     */
    String SEND_IMMEDIATE_IDENTIFICATION = "send-immediate-identification";

    /**
     * Value of {@value #SEND_IMMEDIATE_IDENTIFICATION} if none configured
     */
    boolean DEFAULT_SEND_IMMEDIATE_IDENTIFICATION = true;

    /**
     * Whether to send {@code SSH_MSG_KEXINIT} immediately after sending
     * the client identification string or wait until the severer's one
     * has been received.
     *
     * @see #SEND_IMMEDIATE_IDENTIFICATION
     */
    String SEND_IMMEDIATE_KEXINIT = "send-immediate-kex-init";

    boolean DEFAULT_SEND_KEXINIT = true;

    /**
     * Key used to set the heartbeat interval in milliseconds (0 to disable = default)
     */
    String HEARTBEAT_INTERVAL = "heartbeat-interval";

    /**
     * Default value for {@value #HEARTBEAT_INTERVAL} if none configured
     */
    long DEFAULT_HEARTBEAT_INTERVAL = 0L;

    /**
     * Key used to check the heartbeat request that should be sent to the server
     */
    String HEARTBEAT_REQUEST = "heartbeat-request";

    /**
     * Default value for {@value #HEARTBEAT_REQUEST} is none configured
     */
    String DEFAULT_KEEP_ALIVE_HEARTBEAT_STRING = "keepalive@sshd.apache.org";

    /**
     * Key used to indicate that the heartbeat request is also
     * expecting a reply - time in <U>milliseconds</U> to wait for
     * the reply. If non-positive then no reply is expected (nor requested).
     */
    String HEARTBEAT_REPLY_WAIT = "heartbeat-reply-wait";

    /** Default value for {@value #HEARTBEAT_REPLY_WAIT} if none is configured */
    long DEFAULT_HEARTBEAT_REPLY_WAIT = 0L;

    /**
     * Whether to ignore invalid identities files when pre-initializing
     * the client session
     * @see ClientIdentityLoader#isValidLocation(org.apache.sshd.common.NamedResource)
     */
    String IGNORE_INVALID_IDENTITIES = "ignore-invalid-identities";

    /**
     * Default value of {@value #IGNORE_INVALID_IDENTITIES} if none configured
     */
    boolean DEFAULT_IGNORE_INVALID_IDENTITIES = true;

    /**
     * @return The {@link HostConfigEntryResolver} to use in order to resolve the
     * effective session parameters - never {@code null}
     */
    HostConfigEntryResolver getHostConfigEntryResolver();

    void setHostConfigEntryResolver(HostConfigEntryResolver resolver);
}
