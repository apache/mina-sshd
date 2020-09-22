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

import java.io.IOException;

import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.channel.AbstractChannel;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.throttle.ChannelStreamWriter;
import org.apache.sshd.common.channel.throttle.ChannelStreamWriterResolver;
import org.apache.sshd.common.channel.throttle.DefaultChannelStreamWriter;
import org.apache.sshd.common.util.buffer.Buffer;

public class BogusChannel extends AbstractChannel {
    public BogusChannel() {
        super(false);
    }

    @Override
    protected void doWriteData(byte[] data, int off, long len) throws IOException {
        // ignored
    }

    @Override
    protected void doWriteExtendedData(byte[] data, int off, long len) throws IOException {
        // ignored
    }

    @Override
    protected void sendWindowAdjust(long len) throws IOException {
        // ignored
    }

    @Override
    public OpenFuture open(int recipient, long rwsize, long rmpsize, Buffer buffer) {
        return new DefaultOpenFuture(this, this.futureLock);
    }

    @Override
    public void handleOpenSuccess(int recipient, long rwsize, long rmpsize, Buffer buffer) throws IOException {
        // ignored
    }

    @Override
    public void handleOpenFailure(Buffer buffer) throws IOException {
        // ignored
    }

    @Override
    public ChannelStreamWriterResolver getChannelStreamWriterResolver() {
        return ChannelStreamWriterResolver.NONE;
    }

    @Override
    public ChannelStreamWriter resolveChannelStreamWriter(Channel channel, byte cmd) {
        return new DefaultChannelStreamWriter(channel);
    }

}
