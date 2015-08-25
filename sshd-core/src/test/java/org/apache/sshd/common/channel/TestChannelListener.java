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

import java.util.Collection;
import java.util.concurrent.CopyOnWriteArraySet;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.junit.Assert;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class TestChannelListener extends AbstractLoggingBean implements ChannelListener, NamedResource {
    private final String name;
    private final Collection<Channel> activeChannels = new CopyOnWriteArraySet<>();
    private final Collection<Channel> openChannels = new CopyOnWriteArraySet<>();
    private final Collection<Channel> failedChannels = new CopyOnWriteArraySet<>();

    public TestChannelListener() {
        this("");
    }

    public TestChannelListener(String discriminator) {
        super(discriminator);
        name = discriminator;
    }

    @Override
    public String getName() {
        return name;
    }

    public Collection<Channel> getActiveChannels() {
        return activeChannels;
    }

    @Override
    public void channelInitialized(Channel channel) {
        Assert.assertTrue("Same channel instance re-initialized: " + channel, activeChannels.add(channel));
        log.info("channelInitialized({})", channel);
    }

    public Collection<Channel> getOpenChannels() {
        return openChannels;
    }

    @Override
    public void channelOpenSuccess(Channel channel) {
        Assert.assertTrue("Open channel not activated: " + channel, activeChannels.contains(channel));
        Assert.assertTrue("Same channel instance re-opened: " + channel, openChannels.add(channel));
        log.info("channelOpenSuccess({})", channel);
    }

    public Collection<Channel> getFailedChannels() {
        return failedChannels;
    }

    @Override
    public void channelOpenFailure(Channel channel, Throwable reason) {
        Assert.assertTrue("Failed channel not activated: " + channel, activeChannels.contains(channel));
        Assert.assertTrue("Same channel instance re-failed: " + channel, failedChannels.add(channel));
        log.warn("channelOpenFailure({}) {} : {}", channel, reason.getClass().getSimpleName(), reason.getMessage());
    }

    @Override
    public void channelClosed(Channel channel) {
        Assert.assertTrue("Unknown closed channel instance: " + channel, activeChannels.remove(channel));
        log.info("channelClosed({})", channel);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getName() + "]";
    }
}