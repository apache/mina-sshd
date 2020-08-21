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

package org.apache.sshd.server.shell;

import java.io.IOException;
import java.util.Collection;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.channel.ChannelSession;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface ShellFactorySelector {
    /**
     *
     * @param  channelSession The {@link ChannelSession}
     * @return                The {@link ShellFactory} to use for the channel - {@code null} if none
     * @throws IOException    If failed the selection
     */
    ShellFactory selectShellFactory(ChannelSession channelSession) throws IOException;

    /**
     * Consults each selector whether it wants to provide a factory for the {@link ChannelSession}
     *
     * @param  selectors   The {@link ShellFactorySelector}-s to consult - ignored if {@code null}/empty
     * @param  channel     The {@link ChannelSession} instance
     * @return             The selected {@link ShellFactory} - {@code null} if no selector matched (in which case the
     *                     default factory is used)
     * @throws IOException if any selector threw it
     */
    static ShellFactory selectShellFactory(
            Collection<? extends ShellFactorySelector> selectors, ChannelSession channel)
            throws IOException {
        if (GenericUtils.isEmpty(selectors)) {
            return null;
        }

        for (ShellFactorySelector sel : selectors) {
            ShellFactory factory = sel.selectShellFactory(channel);
            if (factory != null) {
                return factory;
            }
        }

        return null;
    }
}
