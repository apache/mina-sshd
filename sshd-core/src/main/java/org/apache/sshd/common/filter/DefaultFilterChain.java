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
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * A default implementation of a {@link FilterChain}.
 */
public class DefaultFilterChain implements FilterChain {

    private volatile Session session;

    private final CopyOnWriteArrayList<Filter> chain = new CopyOnWriteArrayList<>();

    public DefaultFilterChain() {
        super();
    }

    // Lifecycle methods

    @Override
    public void init() {
        // Nothing
    }

    @Override
    public void adding(Session owner) {
        // Nothing
    }

    @Override
    public void added(Session owner) {
        this.session = session;
    }

    @Override
    public void removing() {
        session = null;
        Filter[] filters = chain.toArray(new Filter[0]);
        for (Filter f : filters) {
            f.removing();
        }
        chain.clear();
        for (Filter f : filters) {
            f.removed(this);
        }
    }

    @Override
    public void removed(Session owner) {
        // Nothing
    }

    @Override
    public Session owner() {
        return session;
    }

    // Filter chain operations

    private Filter notDuplicate(Filter filter) {
        if (chain.indexOf(Objects.requireNonNull(filter)) >= 0) {
            throw new IllegalStateException("Duplicate filter " + filter);
        }
        return filter;
    }

    private void addAt(int i, Filter filter) {
        if (i < 0) {
            throw new NoSuchElementException();
        }
        notDuplicate(filter).adding(this);
        chain.add(i, filter);
        filter.added(this);
    }

    @Override
    public void addFirst(Filter filter) {
        addAt(0, filter);
    }

    @Override
    public void addLast(Filter filter) {
        addAt(chain.size(), filter);
    }

    @Override
    public void addBefore(Filter toAdd, Filter before) {
        addAt(chain.indexOf(Objects.requireNonNull(before)), notDuplicate(toAdd));
    }

    @Override
    public void addAfter(Filter toAdd, Filter after) {
        addAt(chain.indexOf(Objects.requireNonNull(after)) + 1, notDuplicate(toAdd));
    }

    @Override
    public void remove(Filter filter) {
        int i = chain.indexOf(Objects.requireNonNull(filter));
        if (i < 0) {
            throw new IllegalArgumentException("Filter not in filter chain " + filter);
        }
        filter.removing();
        chain.remove(filter);
        filter.removed(this);
    }

    @Override
    public void replace(Filter oldFilter, Filter newFilter) {
        if (oldFilter.equals(Objects.requireNonNull(newFilter))) {
            return;
        }
        int i = chain.indexOf(oldFilter);
        if (i < 0) {
            throw new IllegalArgumentException("Filter not in filter chain " + oldFilter);
        }
        oldFilter.removing();
        chain.remove(i);
        oldFilter.removed(this);
        newFilter.adding(this);
        chain.add(i, newFilter);
        newFilter.added(this);
    }

    @Override
    public Filter getFirst() {
        return chain.isEmpty() ? null : chain.get(0);
    }

    @Override
    public Filter getLast() {
        int i = chain.size();
        if (i == 0) {
            return null;
        }
        return chain.get(i - 1);
    }

    @Override
    public Filter getNext(Filter from) {
        int i = chain.indexOf(from);
        if (i < 0) {
            throw new IllegalArgumentException("Filter not in filter chain: " + from);
        }
        if (i == chain.size() - 1) {
            return null;
        }
        return chain.get(i + 1);
    }

    @Override
    public Filter getPrevious(Filter from) {
        int i = chain.indexOf(from);
        if (i < 0) {
            throw new IllegalArgumentException("Filter not in filter chain: " + from);
        }
        return i == 0 ? null : chain.get(i - 1);
    }

    @Override
    public IoWriteFuture send(Filter current, Buffer message) throws IOException {
        int i = chain.indexOf(current);
        if (i < 0) {
            throw new IllegalArgumentException("Filter not in filter chain: " + current);
        }
        for (int j = i - 1; j >= 0; j--) {
            Filter f = chain.get(j);
            OutputHandler handler = f.out();
            if (handler != null) {
                return handler.send(message);
            }
        }
        throw new IllegalStateException("Fell off filter chain in send from " + current);
    }

    @Override
    public void passOn(Filter current, Readable message) throws Exception {
        int i = chain.indexOf(current);
        if (i < 0) {
            throw new IllegalArgumentException("Filter not in filter chain: " + current);
        }
        for (int j = i + 1; j < chain.size(); j++) {
            Filter f = chain.get(j);
            InputHandler handler = f.in();
            if (handler != null) {
                handler.received(message);
                return;
            }
        }
        throw new IllegalStateException("Unhandled message: fell off filter chain in receive after " + current);
    }

}
