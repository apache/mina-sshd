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

package org.apache.sshd.client.simple;

import org.apache.sshd.common.SshConstants;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SimpleClientConfigurator {
    /**
     * Default connect timeout (msec.) unless {@link #setConnectTimeout(long)} is used
     */
    long DEFAULT_CONNECT_TIMEOUT = Long.MAX_VALUE; // virtually infinite

    /**
     * Default authentication timeout (msec.) unless {@link #setAuthenticationTimeout(long)} is used
     */
    long DEFAULT_AUTHENTICATION_TIMEOUT = Long.MAX_VALUE; // virtually infinite

    int DEFAULT_PORT = SshConstants.DEFAULT_PORT;

    /**
     * @return Current connect timeout (msec.) - always positive
     */
    long getConnectTimeout();

    /**
     * @param timeout Requested connect timeout (msec.) - always positive
     */
    void setConnectTimeout(long timeout);

    /**
     * @return Current authentication timeout (msec.) - always positive
     */
    long getAuthenticationTimeout();

    /**
     * @param timeout Requested authentication timeout (msec.) - always positive
     */
    void setAuthenticationTimeout(long timeout);
}
