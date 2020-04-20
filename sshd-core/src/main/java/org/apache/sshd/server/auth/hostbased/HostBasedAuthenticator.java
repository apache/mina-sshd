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

package org.apache.sshd.server.auth.hostbased;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.sshd.server.session.ServerSession;

/**
 * Invoked when &quot;hostbased&quot; authentication is used
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://tools.ietf.org/html/rfc4252#section-9">RFC 4252 - section 9</A>
 */
@FunctionalInterface
public interface HostBasedAuthenticator {
    /**
     * @param  session        The {@link ServerSession} through which the request was received
     * @param  username       The username attempting to login
     * @param  clientHostKey  The remote client's host {@link PublicKey}
     * @param  clientHostName The reported remote client's host name
     * @param  clientUsername The remote client username
     * @param  certificates   Associated {@link X509Certificate}s - may be {@code null}/empty
     * @return                {@code true} whether authentication is allowed to proceed
     */
    boolean authenticate(
            ServerSession session, String username,
            PublicKey clientHostKey, String clientHostName, String clientUsername, List<X509Certificate> certificates);
}
