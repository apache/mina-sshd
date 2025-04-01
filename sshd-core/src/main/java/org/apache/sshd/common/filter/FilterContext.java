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
import java.util.Objects;

import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.Buffer;

public final class FilterContext {

    volatile FilterContext prev;

    volatile FilterContext next;

    final Filter filter;

    private final FilterChain chain;

    FilterContext(FilterChain chain, Filter filter) {
        this.chain = Objects.requireNonNull(chain);
        this.filter = Objects.requireNonNull(filter);
    }

    /**
     * Retrieves the {@link FilterChain} containing this context.
     *
     * @return the {@link FilterChain}
     */
    public FilterChain chain() {
        return chain;
    }

    /**
     * Pass on an outgoing message to the next filter before this one that has an {@link OutputHandler}.
     *
     * @param  message     being passed on
     * @return             an {@link IoWriteFuture} that is fulfilled when the message has been sent.
     * @throws IOException if an error occurs
     */
    public IoWriteFuture send(Buffer message) throws IOException {
        return chain.send(this, message);
    }

    /**
     * Pass on an incoming message to the next filter after this one that has an {@link InputHandler}.
     *
     * @param  message   being passed on
     * @throws Exception if an error occurs
     */
    public void passOn(Readable message) throws Exception {
        chain.passOn(this, message);
    }
}
