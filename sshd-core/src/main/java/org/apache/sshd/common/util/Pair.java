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
package org.apache.sshd.common.util;

import java.util.Comparator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;

/**
 * Represents an un-modifiable pair of values
 *
 * @param <F> First value type
 * @param <S> Second value type
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Pair<F, S> implements Map.Entry<F, S> {
    @SuppressWarnings("rawtypes")
    private static final Comparator<Map.Entry<Comparable, ?>> BY_KEY_COMPARATOR =
        new Comparator<Map.Entry<Comparable, ?>>() {
            @SuppressWarnings("unchecked")
            @Override
            public int compare(Entry<Comparable, ?> o1, Entry<Comparable, ?> o2) {
                Comparable k1 = o1.getKey();
                Comparable k2 = o2.getKey();
                return k1.compareTo(k2);
            }
    };

    private final F first;
    private final S second;

    public Pair(F first, S second) {
        this.first = first;
        this.second = second;
    }

    @Override
    public final F getKey() {
        return getFirst();
    }

    @Override
    public S getValue() {
        return getSecond();
    }

    @Override
    public S setValue(S value) {
        throw new UnsupportedOperationException("setValue(" + value + ") N/A");
    }

    public final F getFirst() {
        return first;
    }

    public final S getSecond() {
        return second;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getFirst()) * 31 + Objects.hashCode(getSecond());
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }

        if (obj == this) {
            return true;
        }

        if (getClass() != obj.getClass()) {
            return false;
        }

        Pair<?, ?> other = (Pair<?, ?>)obj;
        return Objects.equals(getFirst(), other.getFirst()) && Objects.equals(getSecond(), other.getSecond());
    }

    @Override
    public String toString() {
        return Objects.toString(getFirst()) + ", " + Objects.toString(getSecond());
    }

    /**
     * @param <K> The {@link Comparable} key type
     * @param <V> The associated entry value
     * @return A {@link Comparator} for {@link java.util.Map.Entry}-ies that
     * compares the key values
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public static <K extends Comparable<K>, V> Comparator<Map.Entry<K, V>> byKeyEntryComparator() {
        return (Comparator) BY_KEY_COMPARATOR;
    }
}