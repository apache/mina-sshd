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

import org.apache.sshd.common.FactoryManager;

/**
 * The <code>ClientFactoryManager</code> enable the retrieval of additional
 * configuration needed specifically for the client side.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ClientFactoryManager extends FactoryManager {

    /**
     * Key used to set the heartbeat interval in milliseconds (0 to disable which is the default value)
     */
    public static final String HEARTBEAT_INTERVAL = "hearbeat-interval";

    /**
     * Key used to check the hearbeat request that should be sent to the server (default is keepalive@sshd.apache.org).
     */
    public static final String HEARTBEAT_REQUEST = "heartbeat-request";

    /**
     * Retrieve the server key verifier to be used to check the key when connecting
     * to an ssh server.
     *
     * @return the server key verifier to use
     */
    ServerKeyVerifier getServerKeyVerifier();

}
