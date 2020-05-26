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

package org.apache.sshd.common.util.helper;

import java.util.Collections;
import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * Creates a &quot;smooth&quot; wrapping {@link Iterable} using several underlying ones to provide the values. The
 * &quot;lazy&quot; denomination is due to the fact that no iterable is consulted until the one(s) before it have been
 * fully exhausted.
 *
 * @param  <T> Type of element being iterared
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LazyIterablesConcatenator<T> implements Iterable<T> {
    private final Iterable<? extends Iterable<? extends T>> iterables;

    public LazyIterablesConcatenator(Iterable<? extends Iterable<? extends T>> iterables) {
        this.iterables = iterables;
    }

    public Iterable<? extends Iterable<? extends T>> getIterables() {
        return iterables;
    }

    @Override
    public Iterator<T> iterator() {
        return new Iterator<T>() {
            @SuppressWarnings("synthetic-access")
            private final Iterator<? extends Iterable<? extends T>> itit
                    = (iterables == null) ? Collections.emptyIterator() : iterables.iterator();
            private Iterator<? extends T> currentIterator;
            private boolean finished;

            @Override
            public boolean hasNext() {
                if (finished) {
                    return false;
                }

                // Do we have a current iterator, and if so does it still have values in it
                if ((currentIterator != null) && currentIterator.hasNext()) {
                    return true;
                }

                while (itit.hasNext()) {
                    Iterable<? extends T> currentIterable = itit.next();
                    currentIterator = currentIterable.iterator();
                    if (currentIterator.hasNext()) {
                        return true;
                    }
                }

                // exhausted all
                finished = true;
                return false;
            }

            @Override
            public T next() {
                if (finished) {
                    throw new NoSuchElementException("All elements have been exhausted");
                }

                if (currentIterator == null) {
                    throw new IllegalStateException("'next()' called without a preceding 'hasNext()' query");
                }

                return currentIterator.next();
            }

            @Override
            public String toString() {
                return Iterator.class.getSimpleName() + "[lazy-concat]";
            }
        };
    }

    @Override
    public String toString() {
        return Iterable.class.getSimpleName() + "[lazy-concat]";
    }

    /**
     * @param  <T>       Type if iterated element
     * @param  iterables The iterables to concatenate - ignored if {@code null}
     * @return           An {@link Iterable} that goes over all the elements in the wrapped iterables one after the
     *                   other. The denomination &quot;lazy&quot; indicates that no iterable is consulted until the
     *                   previous one has been fully exhausted.
     */
    public static <T> Iterable<T> lazyConcatenateIterables(Iterable<? extends Iterable<? extends T>> iterables) {
        return (iterables == null) ? Collections.emptyList() : new LazyIterablesConcatenator<>(iterables);
    }
}
