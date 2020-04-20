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
package org.apache.sshd.server.forward;

import org.apache.sshd.common.session.Session;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface X11ForwardingFilter {
    // According to https://www.freebsd.org/cgi/man.cgi?query=sshd_config&sektion=5
    X11ForwardingFilter DEFAULT = (session, request) -> false;

    /**
     * <p>
     * Determine if the session may arrange for X11 forwarding.
     * </p>
     *
     * <p>
     * This server process will open a new listen socket locally and export the address in the environment so X11
     * clients can be tunneled to the user's X11 display server.
     * </p>
     *
     * @param  session     The {@link Session} requesting permission to forward X11 connections.
     * @param  requestType The request type string that triggered this call
     * @return             true if the X11 forwarding is permitted, false if denied.
     */
    boolean canForwardX11(Session session, String requestType);

    static X11ForwardingFilter of(boolean enabled) {
        return (session, request) -> enabled;
    }
}
