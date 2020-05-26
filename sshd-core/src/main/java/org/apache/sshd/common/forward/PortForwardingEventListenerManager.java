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

/**
 * Marker interface for classes that allow to add/remove port forwarding listeners. <B>Note:</B> if adding/removing
 * listeners while tunnels are being established and/or torn down there are no guarantees as to the order of the calls
 * to the recently added/removed listener's methods in the interim. The correct order is guaranteed only as of the
 * <U>next</U> tunnel after the listener has been added/removed.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PortForwardingEventListenerManager {
    /**
     * Add a port forwarding listener
     *
     * @param listener The {@link PortForwardingEventListener} to add - never {@code null}
     */
    void addPortForwardingEventListener(PortForwardingEventListener listener);

    /**
     * Remove a port forwarding listener
     *
     * @param listener The {@link PortForwardingEventListener} to remove - ignored if {@code null}
     */
    void removePortForwardingEventListener(PortForwardingEventListener listener);

    /**
     * @return A proxy listener representing all the currently registered listener through this manager
     */
    PortForwardingEventListener getPortForwardingEventListenerProxy();
}
