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
package org.apache.sshd.util.test;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

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
    private final Semaphore activeChannelsCounter = new Semaphore(0);
    private final Collection<Channel> openChannels = new CopyOnWriteArraySet<>();
    private final Semaphore openChannelsCounter = new Semaphore(0);
    private final Collection<Channel> failedChannels = new CopyOnWriteArraySet<>();
    private final Semaphore failedChannelsCounter = new Semaphore(0);
    private final Map<Channel, Collection<String>> channelStateHints = new ConcurrentHashMap<>();
    private final Semaphore chanelStateCounter = new Semaphore(0);
    private final Semaphore modificationsCounter = new Semaphore(0);
    private final Semaphore closedChannelsCounter = new Semaphore(0);

    public TestChannelListener(String discriminator) {
        super(discriminator);
        name = discriminator;
    }

    public boolean waitForModification(long timeout, TimeUnit unit) throws InterruptedException {
        return modificationsCounter.tryAcquire(timeout, unit);
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
        activeChannelsCounter.release();
        modificationsCounter.release();
        log.info("channelInitialized({})", channel);
    }

    public boolean waitForActiveChannelsChange(long timeout, TimeUnit unit) throws InterruptedException {
        return activeChannelsCounter.tryAcquire(timeout, unit);
    }

    public Collection<Channel> getOpenChannels() {
        return openChannels;
    }

    @Override
    public void channelOpenSuccess(Channel channel) {
        Assert.assertTrue("Open channel not activated: " + channel, activeChannels.contains(channel));
        Assert.assertTrue("Same channel instance re-opened: " + channel, openChannels.add(channel));
        openChannelsCounter.release();
        modificationsCounter.release();
        log.info("channelOpenSuccess({})", channel);
    }

    public boolean waitForOpenChannelsChange(long timeout, TimeUnit unit) throws InterruptedException {
        return openChannelsCounter.tryAcquire(timeout, unit);
    }

    public Collection<Channel> getFailedChannels() {
        return failedChannels;
    }

    @Override
    public void channelOpenFailure(Channel channel, Throwable reason) {
        Assert.assertTrue("Failed channel not activated: " + channel, activeChannels.contains(channel));
        Assert.assertTrue("Same channel instance re-failed: " + channel, failedChannels.add(channel));
        failedChannelsCounter.release();
        modificationsCounter.release();
        warn("channelOpenFailure({}) {} : {}", channel, reason.getClass().getSimpleName(), reason.getMessage(), reason);
    }

    public boolean waitForFailedChannelsChange(long timeout, TimeUnit unit) throws InterruptedException {
        return failedChannelsCounter.tryAcquire(timeout, unit);
    }

    @Override
    public void channelClosed(Channel channel, Throwable reason) {
        Assert.assertTrue("Unknown closed channel instance: " + channel, activeChannels.remove(channel));
        activeChannelsCounter.release();
        closedChannelsCounter.release();
        modificationsCounter.release();
        log.info("channelClosed({})", channel);
    }

    public boolean waitForClosedChannelsChange(long timeout, TimeUnit unit) throws InterruptedException {
        return closedChannelsCounter.tryAcquire(timeout, unit);
    }

    public Map<Channel, Collection<String>> getChannelStateHints() {
        return channelStateHints;
    }

    @Override
    public void channelStateChanged(Channel channel, String hint) {
        Collection<String> hints;
        synchronized (channelStateHints) {
            hints = channelStateHints.get(channel);
            if (hints == null) {
                hints = new CopyOnWriteArrayList<>();
                channelStateHints.put(channel, hints);
            }
        }

        hints.add(hint);
        chanelStateCounter.release();
        modificationsCounter.release();
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getName() + "]";
    }
}
