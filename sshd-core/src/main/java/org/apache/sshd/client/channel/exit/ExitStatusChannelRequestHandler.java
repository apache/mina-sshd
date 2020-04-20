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
package org.apache.sshd.client.channel.exit;

import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.util.EventNotifier;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://tools.ietf.org/html/rfc4254#section-6.10">RFC4254 section 6.10</A>
 */
public class ExitStatusChannelRequestHandler extends AbstractChannelExitRequestHandler<Integer> {
    public static final String NAME = "exit-status";

    public ExitStatusChannelRequestHandler(AtomicReference<Integer> holder, EventNotifier<? super String> notifier) {
        super(holder, notifier);
    }

    @Override
    public final String getName() {
        return NAME;
    }

    @Override
    protected Integer processRequestValue(Channel channel, String request, Buffer buffer) throws Exception {
        return processRequestValue(channel, buffer.getInt());
    }

    protected Integer processRequestValue(Channel channel, int exitStatus) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("processRequestValue({}) status={}", channel, exitStatus);
        }

        return exitStatus;
    }
}
