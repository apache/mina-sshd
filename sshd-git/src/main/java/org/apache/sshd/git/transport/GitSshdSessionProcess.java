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

package org.apache.sshd.git.transport;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class GitSshdSessionProcess extends Process {
    public static final Set<ClientChannelEvent> CLOSE_WAIT_EVENTS
            = Collections.unmodifiableSet(EnumSet.of(ClientChannelEvent.CLOSED));

    protected final ChannelExec channel;
    protected final String commandName;
    protected final long waitTimeout;
    protected final Logger log;

    public GitSshdSessionProcess(ChannelExec channel, String commandName, int timeoutSec) {
        this.channel = Objects.requireNonNull(channel, "No exec channel");
        this.commandName = commandName;
        this.waitTimeout = (timeoutSec > 0) ? TimeUnit.SECONDS.toMillis(timeoutSec) : Long.MAX_VALUE;
        this.log = LoggerFactory.getLogger(getClass());
    }

    @Override
    public OutputStream getOutputStream() {
        return channel.getInvertedIn();
    }

    @Override
    public InputStream getInputStream() {
        return channel.getInvertedOut();
    }

    @Override
    public InputStream getErrorStream() {
        return channel.getInvertedErr();
    }

    @Override // TODO in Java-8 implement also waitFor(long, TimeUnit)
    public int waitFor() throws InterruptedException {
        boolean traceEnabled = log.isTraceEnabled();
        if (traceEnabled) {
            log.trace("waitFor({}) channel={} waiting {} millis", commandName, channel, waitTimeout);
        }

        Collection<ClientChannelEvent> res = channel.waitFor(CLOSE_WAIT_EVENTS, waitTimeout);
        if (traceEnabled) {
            log.trace("waitFor({}) channel={} events={}", commandName, channel, res);
        }

        if (res.contains(ClientChannelEvent.CLOSED)) {
            return 0;
        } else {
            return -1;
        }
    }

    @Override
    public int exitValue() {
        Integer status = channel.getExitStatus();
        if (status == null) { // NOTE: MUST use IllegalThreadStateException as per the Javadoc
            throw new IllegalThreadStateException("No channel status available");
        }
        if (log.isTraceEnabled()) {
            log.trace("exitValue({}) channel={}, timeout={} millis.: {}",
                    commandName, channel, waitTimeout, status);
        }
        return status;
    }

    @Override
    public void destroy() {
        if (channel.isOpen()) {
            channel.close(true);
        }
    }

    @Override
    public String toString() {
        return "channel=" + channel + ", cmd=" + commandName + ", timeout=" + waitTimeout;
    }
}
