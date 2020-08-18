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

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.channel.AbstractChannelRequestHandler;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.util.EventNotifier;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Provides a common base class for channel request handlers that deal with various &quot;<code>exit-XXX</code>&quot;
 * requests. Once such a request has been successfully processed, an {@link EventNotifier} can be invoked indicating the
 * processed event.
 *
 * @param  <V> Type of data being extracted from the request when processed
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractChannelExitRequestHandler<V> extends AbstractChannelRequestHandler implements NamedResource {
    protected final AtomicReference<V> holder;
    protected final EventNotifier<? super String> notifier;

    /**
     * @param holder   An {@link AtomicReference} that will hold the extracted request data
     * @param notifier An {@link EventNotifier} to be invoked when request is successfully processed and the holder has
     *                 been updated with the processed request data
     */
    protected AbstractChannelExitRequestHandler(AtomicReference<V> holder, EventNotifier<? super String> notifier) {
        this.holder = Objects.requireNonNull(holder, "No exit status holder");
        this.notifier = Objects.requireNonNull(notifier, "No event notifier");
    }

    @Override // see RFC4254 section 6.10
    public Result process(Channel channel, String request, boolean wantReply, Buffer buffer) throws Exception {
        String name = getName();
        if (name.equals(request)) {
            V value = processRequestValue(channel, request, buffer);
            if (value != null) {
                if (log.isDebugEnabled()) {
                    log.debug("process({})[{}] wantReply={}: {}", channel, request, wantReply, value);
                }

                holder.set(value);
                notifyStateChanged(channel, request, value);
                return Result.ReplySuccess;
            }
        }

        if (log.isTraceEnabled()) {
            log.trace("process({}) wantReply={} ignore request={}", channel, wantReply, request);
        }
        return Result.Unsupported;
    }

    /**
     * Invoked by default from {@link #process(Channel, String, boolean, Buffer)} when a request matching the handler's
     * name is received
     *
     * @param  channel   The {@link Channel} through which the request was received
     * @param  request   The received request - <B>Note:</B> guaranteed to match the handler's name if invoked from
     *                   {@link #process(Channel, String, boolean, Buffer)}
     * @param  buffer    The received {@link Buffer} for extracting the data
     * @return           The extracted data - if {@code null} then request is ignored and {@code Unsupported} is
     *                   returned
     * @throws Exception If failed to process the received request buffer
     */
    protected abstract V processRequestValue(Channel channel, String request, Buffer buffer) throws Exception;

    /**
     * Notifies that some change has been made to the data in the holder. The reported event is obtained via the
     * {@link #getEvent(Channel, String, Object)} call
     *
     * @param channel The {@link Channel} through which the request was received
     * @param request The processed request
     * @param value   The processed value
     */
    protected void notifyStateChanged(Channel channel, String request, V value) {
        String event = getEvent(channel, request, value);
        try {
            notifier.notifyEvent(event);
            if (log.isDebugEnabled()) {
                log.debug("notifyStateChanged({})[{}] event={}", channel, request, event);
            }
        } catch (Exception e) {
            warn("notifyStateChanged({})[{}] Failed ({}) to notify event={}: {}",
                    channel, request, e.getClass().getSimpleName(), event, e.getMessage(), e);
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * @param  channel The {@link Channel} through which the request was received
     * @param  request The processed request
     * @param  value   The processed value
     * @return         The event name to be used - default: {@link #getName()} value
     */
    protected String getEvent(Channel channel, String request, V value) {
        return getName();
    }
}
