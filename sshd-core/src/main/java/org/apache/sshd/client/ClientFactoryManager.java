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
package org.apache.sshd.client;

import java.util.List;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;

/**
 * The <code>ClientFactoryManager</code> enable the retrieval of additional
 * configuration needed specifically for the client side.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ClientFactoryManager extends FactoryManager {

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
     * Ordered comma separated list of authentications methods.
     * Authentications methods accepted by the server will be tried in the given order.
     * If not configured or {@code null}/empty, then the session's {@link #getUserAuthFactories()}
     * is used as-is
     */
    String PREFERRED_AUTHS = "preferred-auths";

    /**
     * Specifies the number of password prompts before giving up.
     * The argument to this keyword must be an integer.
     */
    String PASSWORD_PROMPTS = "password-prompts";
        /**
         * Default value for {@link #PASSWORD_PROMPTS} if none configured
         */
        int DEFAULT_PASSWORD_PROMPTS = 3;

    /**
     * Retrieve the server key verifier to be used to check the key when connecting
     * to an ssh server.
     *
     * @return the server key verifier to use
     */
    ServerKeyVerifier getServerKeyVerifier();

    /**
     * @return A {@link UserInteraction} object to communicate with the user
     * (may be {@code null} to indicate that no such communication is allowed)
     */
    UserInteraction getUserInteraction();

    /**
     * @return a {@link List} of {@link UserAuth} {@link NamedFactory}-ies - never
     * {@code null}/empty
     */
    List<NamedFactory<UserAuth>> getUserAuthFactories();

}
