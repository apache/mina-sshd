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

package org.apache.sshd.common.channel;

import java.io.IOException;
import java.util.Collection;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.session.Session;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ChannelFactory extends NamedResource {
    /**
     * @param  session     The {@link Session} through which the request is made
     * @return             The relevant {@link Channel}
     * @throws IOException If failed to create the requested instance
     */
    Channel createChannel(Session session) throws IOException;

    /**
     * @param  session     The {@link Session} through which the request is made
     * @param  factories   The available factories
     * @param  name        The required factory name to use
     * @return             The created {@link Channel} - {@code null} if no match found
     * @throws IOException If failed to create the requested instance
     */
    static Channel createChannel(
            Session session, Collection<? extends ChannelFactory> factories, String name)
            throws IOException {
        ChannelFactory f = NamedResource.findByName(name, String.CASE_INSENSITIVE_ORDER, factories);
        if (f != null) {
            return f.createChannel(session);
        } else {
            return null;
        }
    }
}
