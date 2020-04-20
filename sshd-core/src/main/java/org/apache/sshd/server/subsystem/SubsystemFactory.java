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

package org.apache.sshd.server.subsystem;

import java.io.IOException;
import java.util.Collection;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SubsystemFactory extends NamedResource {
    /**
     * @param  channel     The {@link ChannelSession} through which the command has been received
     * @return             a non {@code null} {@link Command} instance representing the subsystem to be run
     * @throws IOException if failed to create the instance
     */
    Command createSubsystem(ChannelSession channel) throws IOException;

    /**
     * @param  channel     The {@link ChannelSession} through which the command has been received
     * @param  factories   The available {@link SubsystemFactory}-ies - ignored if {@code null}/empty
     * @param  name        Requested subsystem name
     * @return             The created {@link Command} instance representing the subsystem to be run - {@code null} if
     *                     no match found
     * @throws IOException If found a matching factory but failed to create the command instance
     */
    static Command createSubsystem(
            ChannelSession channel, Collection<? extends SubsystemFactory> factories, String name)
            throws IOException {
        SubsystemFactory factory = NamedResource.findByName(name, String.CASE_INSENSITIVE_ORDER, factories);
        if (factory != null) {
            return factory.createSubsystem(channel);
        } else {
            return null;
        }
    }
}
