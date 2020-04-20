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
import java.util.Objects;

import org.apache.sshd.common.util.GenericUtils;

/**
 * An {@link Iterator} that selects only objects of a certain type from the underlying available ones. The
 * &quot;lazy&quot; denomination is due to the fact that selection occurs only when {@link #hasNext()} is called
 *
 * @param  <T> Type of iterated element
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LazyMatchingTypeIterator<T> implements Iterator<T> {
    protected boolean finished;
    protected T nextValue;

    private final Iterator<?> values;
    private final Class<T> type;

    public LazyMatchingTypeIterator(Iterator<?> values, Class<T> type) {
        this.values = values;
        this.type = Objects.requireNonNull(type, "No type selector specified");
    }

    public Iterator<?> getValues() {
        return values;
    }

    public Class<T> getType() {
        return type;
    }

    @Override
    public boolean hasNext() {
        if (finished) {
            return false;
        }

        nextValue = GenericUtils.selectNextMatchingValue(getValues(), getType());
        if (nextValue == null) {
            finished = true;
        }

        return !finished;
    }

    @Override
    public T next() {
        if (finished) {
            throw new NoSuchElementException("All values have been exhausted");
        }
        if (nextValue == null) {
            throw new IllegalStateException("'next()' called without asking 'hasNext()'");
        }

        T v = nextValue;
        nextValue = null; // so it will be re-fetched when 'hasNext' is called
        return v;
    }

    @Override
    public String toString() {
        Class<?> t = getType();
        return Iterator.class.getSimpleName() + "[lazy-select](" + t.getSimpleName() + ")";
    }

    /**
     * @param  <T>    Type if iterated element
     * @param  values The source values - ignored if {@code null}
     * @param  type   The (never @code null) type of values to select - any value whose type is assignable to this type
     *                will be selected by the iterator.
     * @return        An {@link Iterator} whose {@code next()} call selects only values matching the specific type.
     *                <b>Note:</b> the matching values are not pre-calculated (hence the &quot;lazy&quot; denomination)
     *                - i.e., the match is performed only when {@link Iterator#hasNext()} is called.
     */
    public static <T> Iterator<T> lazySelectMatchingTypes(Iterator<?> values, Class<T> type) {
        Objects.requireNonNull(type, "No type selector specified");
        return (values == null) ? Collections.emptyIterator() : new LazyMatchingTypeIterator<>(values, type);
    }
}
