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
import java.util.Objects;

/**
 * Provides a selective {@link Iterable} over values that match a specific type out of all available. The
 * &quot;lazy&quot; denomination is due to the fact that the next matching value is calculated on-the-fly every time
 * {@link Iterator#hasNext()} is called
 *
 * @param  <T> Type of element being selected
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LazyMatchingTypeIterable<T> implements Iterable<T> {
    private final Iterable<?> values;
    private final Class<T> type;

    public LazyMatchingTypeIterable(Iterable<?> values, Class<T> type) {
        this.values = values;
        this.type = Objects.requireNonNull(type, "No type selector specified");
    }

    public Iterable<?> getValues() {
        return values;
    }

    public Class<T> getType() {
        return type;
    }

    @Override
    public Iterator<T> iterator() {
        Iterable<?> vals = getValues();
        if (vals == null) {
            return Collections.emptyIterator();
        }

        return LazyMatchingTypeIterator.lazySelectMatchingTypes(vals.iterator(), getType());
    }

    @Override
    public String toString() {
        Class<?> t = getType();
        return Iterable.class.getSimpleName() + "[lazy-select](" + t.getSimpleName() + ")";
    }

    /**
     * @param  <T>    Type if iterated element
     * @param  values The source values - ignored if {@code null}
     * @param  type   The (never @code null) type of values to select - any value whose type is assignable to this type
     *                will be selected by the iterator.
     * @return        {@link Iterable} whose {@link Iterator} selects only values matching the specific type.
     *                <b>Note:</b> the matching values are not pre-calculated (hence the &quot;lazy&quot; denomination)
     *                - i.e., the match is performed only when {@link Iterator#hasNext()} is called.
     */
    public static <T> Iterable<T> lazySelectMatchingTypes(Iterable<?> values, Class<T> type) {
        Objects.requireNonNull(type, "No type selector specified");
        return (values == null) ? Collections.emptyList() : new LazyMatchingTypeIterable<>(values, type);
    }
}
