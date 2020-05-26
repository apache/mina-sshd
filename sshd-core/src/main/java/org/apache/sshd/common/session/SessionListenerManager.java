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

package org.apache.sshd.common.session;

/**
 * Marker interface for classes that allow to add/remove session listeners. <B>Note:</B> if adding/removing listeners
 * while connections are being established and/or torn down there are no guarantees as to the order of the calls to the
 * recently added/removed listener's methods in the interim. The correct order is guaranteed only as of the <U>next</U>
 * session after the listener has been added/removed.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SessionListenerManager {
    /**
     * Add a session listener.
     *
     * @param listener The {@link SessionListener} to add - not {@code null}
     */
    void addSessionListener(SessionListener listener);

    /**
     * Remove a session listener.
     *
     * @param listener The {@link SessionListener} to remove
     */
    void removeSessionListener(SessionListener listener);

    /**
     * @return A (never {@code null} proxy {@link SessionListener} that represents all the currently registered
     *         listeners. Any method invocation on the proxy is replicated to the currently registered listeners
     */
    SessionListener getSessionListenerProxy();
}
