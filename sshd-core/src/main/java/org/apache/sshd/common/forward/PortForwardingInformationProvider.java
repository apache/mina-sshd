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

package org.apache.sshd.common.forward;

import java.util.List;
import java.util.Map;
import java.util.NavigableSet;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PortForwardingInformationProvider {
    /**
     * @return A {@link List} <u>snapshot</u> of the currently started local port forward bindings
     */
    List<SshdSocketAddress> getStartedLocalPortForwards();

    /**
     * @param  port The port number
     * @return      The local bound {@link SshdSocketAddress}-es for the port
     * @see         #isLocalPortForwardingStartedForPort(int) isLocalPortForwardingStartedForPort
     * @see         #getStartedLocalPortForwards()
     */
    List<SshdSocketAddress> getBoundLocalPortForwards(int port);

    /**
     * @return A <u>snapshot</u> of the currently bound forwarded local ports as &quot;pairs&quot; of local/remote
     *         {@link SshdSocketAddress}-es
     */
    List<Map.Entry<SshdSocketAddress, SshdSocketAddress>> getLocalForwardsBindings();

    /**
     * Test if local port forwarding is started
     *
     * @param  port The local port
     * @return      {@code true} if local port forwarding is started
     * @see         #getBoundLocalPortForwards(int) getBoundLocalPortForwards
     */
    default boolean isLocalPortForwardingStartedForPort(int port) {
        return GenericUtils.isNotEmpty(getBoundLocalPortForwards(port));
    }

    /**
     * @return A {@link NavigableSet} <u>snapshot</u> of the currently started remote port forwards
     */
    NavigableSet<Integer> getStartedRemotePortForwards();

    /**
     * @param  port The port number
     * @return      The remote bound {@link SshdSocketAddress} for the port - {@code null} if none bound
     * @see         #isRemotePortForwardingStartedForPort(int) isRemotePortForwardingStartedForPort
     * @see         #getStartedRemotePortForwards()
     */
    SshdSocketAddress getBoundRemotePortForward(int port);

    /**
     * @return A <u>snapshot</u> of the currently bound forwarded remote ports as &quot;pairs&quot; of port + bound
     *         {@link SshdSocketAddress}
     */
    List<Map.Entry<Integer, SshdSocketAddress>> getRemoteForwardsBindings();

    /**
     * Test if remote port forwarding is started
     *
     * @param  port The remote port
     * @return      {@code true} if remote port forwarding is started
     * @see         #getBoundRemotePortForward(int) getBoundRemotePortForward
     */
    default boolean isRemotePortForwardingStartedForPort(int port) {
        return getBoundRemotePortForward(port) != null;
    }
}
