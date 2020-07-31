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

package org.apache.sshd.client.config.hosts;

import java.io.IOException;
import java.net.SocketAddress;

import org.apache.sshd.common.AttributeRepository;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://linux.die.net/man/5/ssh_config">ssh_config</A>
 */
@FunctionalInterface
public interface HostConfigEntryResolver {
    /**
     * An &quot;empty&quot; implementation that does not resolve any entry - i.e., uses the original entry as-is
     */
    HostConfigEntryResolver EMPTY = new HostConfigEntryResolver() {
        @Override
        public HostConfigEntry resolveEffectiveHost(
                String host, int port, SocketAddress localAddress, String username, String proxyJump,
                AttributeRepository context)
                throws IOException {
            return null;
        }

        @Override
        public String toString() {
            return "EMPTY";
        }
    };

    /**
     * Invoked when creating a new client session in order to allow for overriding of the original parameters
     *
     * @param  host         The requested host - never {@code null}/empty
     * @param  port         The requested port
     * @param  localAddress Optional binding endpoint for the local peer
     * @param  username     The requested username
     * @param  proxyJump    The requested proxyJump
     * @param  context      An optional &quot;context&quot; provided during the connection request (to be attached to
     *                      the established session if successfully connected)
     * @return              A {@link HostConfigEntry} for the actual target - {@code null} if use original parameters.
     *                      <B>Note:</B> if any identity files are attached to the configuration then they must point to
     *                      <U>existing</U> locations. This means that any macros such as <code>~, %d, %h</code>, etc.
     *                      must be resolved <U>prior</U> to returning the value
     * @throws IOException  If failed to resolve the configuration
     */
    HostConfigEntry resolveEffectiveHost(
            String host, int port, SocketAddress localAddress, String username, String proxyJump, AttributeRepository context)
            throws IOException;
}
