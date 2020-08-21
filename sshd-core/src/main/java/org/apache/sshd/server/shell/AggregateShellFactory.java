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
import java.util.Collections;
import java.util.Objects;

import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;

/**
 * Provides different shell(s) based on some criteria of the provided {@link ChannelSession}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class AggregateShellFactory extends AbstractLoggingBean implements ShellFactory, ShellFactorySelector {
    protected final ShellFactory defaultFactory;
    protected final Collection<? extends ShellFactorySelector> selectors;

    /**
     * @param selectors Selector {@link ShellFactorySelector}-s being consulted whether they wish to provide a
     *                  {@link ShellFactory} for the provided {@link ChannelSession} argument. If a selector returns
     *                  {@code null} then the next in line is consulted. If no match found then the default
     *                  {@link InteractiveProcessShellFactory} is used
     */
    public AggregateShellFactory(
                                 Collection<? extends ShellFactorySelector> selectors) {
        this(selectors, InteractiveProcessShellFactory.INSTANCE);
    }

    /**
     * @param selectors      Selector {@link ShellFactorySelector}-s being consulted whether they wish to provide a
     *                       {@link ShellFactory} for the provided {@link ChannelSession} argument. If a selector
     *                       returns {@code null} then the next in line is consulted.
     * @param defaultFactory The (mandatory) default {@link ShellFactory} to use if no selector matched
     */
    public AggregateShellFactory(
                                 Collection<? extends ShellFactorySelector> selectors, ShellFactory defaultFactory) {
        this.selectors = (selectors == null) ? Collections.emptyList() : selectors;
        this.defaultFactory = Objects.requireNonNull(defaultFactory, "No default factory provided");
    }

    @Override
    public Command createShell(ChannelSession channel) throws IOException {
        ShellFactory factory = selectShellFactory(channel);
        if (factory == null) {
            if (log.isDebugEnabled()) {
                log.debug("createShell({}) using default factory={}", channel, defaultFactory);
            }

            factory = defaultFactory;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("createShell({}) using selected factory={}", channel, factory);
            }
        }

        return factory.createShell(channel);
    }

    @Override
    public ShellFactory selectShellFactory(ChannelSession channel) throws IOException {
        return ShellFactorySelector.selectShellFactory(selectors, channel);
    }
}
