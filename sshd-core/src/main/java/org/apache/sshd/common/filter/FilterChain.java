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
package org.apache.sshd.common.filter;

import java.io.IOException;

import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * A general chain of {@link Filter}s.
 */
public interface FilterChain {

    boolean isEmpty();

    /**
     * Adds the given filter at the front of the filter chain.
     *
     * @param filter to add
     */
    FilterContext addFirst(Filter filter);

    /**
     * Adds the given filter at the end of the filter chain.
     *
     * @param filter to add
     */
    FilterContext addLast(Filter filter);

    FilterContext addBefore(Filter toAdd, FilterContext before);

    FilterContext addAfter(Filter toAdd, FilterContext after);

    Filter getFirst();

    Filter getLast();

    /**
     * Pass on an outgoing message to the next filter before {@code current} that has an {@link OutputHandler}.
     *
     * @param  current     {@link Filter} that is passing on the message
     * @param  cmd         the SSH command code of the buffer being written; must also be included in the buffer
     * @param  message     being passed on
     * @return             an {@link IoWriteFuture} that is fulfilled when the message has been sent.
     * @throws IOException if an error occurs
     */
    IoWriteFuture send(FilterContext current, int cmd, Buffer message) throws IOException;

    /**
     * Pass on an incoming message to the next filter after {@code current} that has an {@link InputHandler}.
     *
     * @param  current   {@link Filter} that is passing on the message
     * @param  message   being passed on
     * @throws Exception if an error occurs
     */
    void passOn(FilterContext current, Readable message) throws Exception;
}
