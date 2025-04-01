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

/**
 * A default implementation of a {@link FilterChain}.
 */
public class DefaultFilterChain implements FilterChain {

    private FilterContext head;

    private FilterContext tail;

    public DefaultFilterChain() {
        super();
    }

    @Override
    public boolean isEmpty() {
        return head == null;
    }

    @Override
    public synchronized FilterContext addFirst(Filter filter) {
        FilterContext ctx = new FilterContext(this, filter);
        filter.adding(ctx);
        ctx.prev = null;
        ctx.next = head;
        if (head != null) {
            ctx.next.prev = ctx;
        }
        head = ctx;
        if (tail == null) {
            tail = ctx;
        }
        filter.added(ctx);
        return ctx;
    }

    @Override
    public synchronized FilterContext addLast(Filter filter) {
        FilterContext ctx = new FilterContext(this, filter);
        filter.adding(ctx);
        ctx.next = null;
        ctx.prev = tail;
        if (tail != null) {
            ctx.prev.next = ctx;
        }
        tail = ctx;
        if (head == null) {
            head = ctx;
        }
        filter.added(ctx);
        return ctx;
    }

    @Override
    public synchronized FilterContext addBefore(Filter filter, FilterContext before) {
        Objects.requireNonNull(before);
        FilterContext ctx = new FilterContext(this, filter);
        filter.adding(ctx);
        ctx.next = before;
        ctx.prev = before.prev;
        before.prev = ctx;
        if (ctx.prev == null) {
            head = ctx;
        } else {
            ctx.prev.next = ctx;
        }
        filter.added(ctx);
        return ctx;
    }

    @Override
    public synchronized FilterContext addAfter(Filter filter, FilterContext after) {
        Objects.requireNonNull(after);
        FilterContext ctx = new FilterContext(this, filter);
        filter.adding(ctx);
        ctx.prev = after;
        ctx.next = after.next;
        after.next = ctx;
        if (ctx.next == null) {
            tail = ctx;
        } else {
            ctx.next.prev = ctx;
        }
        filter.added(ctx);
        return ctx;
    }

    @Override
    public synchronized Filter getFirst() {
        return head == null ? null : head.filter;
    }

    @Override
    public synchronized Filter getLast() {
        return tail == null ? null : tail.filter;
    }

    @Override
    public IoWriteFuture send(FilterContext current, Buffer message) throws IOException {
        FilterContext ctx = current.prev;
        while (ctx != null) {
            OutputHandler handler = ctx.filter.out();
            if (handler != null) {
                return handler.send(message);
            }
            ctx = ctx.prev;
        }
        throw new IllegalStateException("Fell off filter chain in send from " + current.filter);
    }

    @Override
    public void passOn(FilterContext current, Readable message) throws Exception {
        FilterContext ctx = current.next;
        while (ctx != null) {
            InputHandler handler = ctx.filter.in();
            if (handler != null) {
                handler.received(message);
                return;
            }
            ctx = ctx.next;
        }
        throw new IllegalStateException("Unhandled message: fell off filter chain in receive after " + current.filter);
    }

}
