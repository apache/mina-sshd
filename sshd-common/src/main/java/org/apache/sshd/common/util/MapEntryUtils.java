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

import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Supplier;

/**
 * Represents an un-modifiable pair of values
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class MapEntryUtils {
    @SuppressWarnings({ "rawtypes", "unchecked" })
    private static final Comparator<Map.Entry<Comparable, ?>> BY_KEY_COMPARATOR = (o1, o2) -> {
        Comparable k1 = o1.getKey();
        Comparable k2 = o2.getKey();
        return k1.compareTo(k2);
    };

    private MapEntryUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * @param  <K> The {@link Comparable} key type
     * @param  <V> The associated entry value
     * @return     A {@link Comparator} for {@link java.util.Map.Entry}-ies that compares the key values
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public static <K extends Comparable<K>, V> Comparator<Map.Entry<K, V>> byKeyEntryComparator() {
        return (Comparator) BY_KEY_COMPARATOR;
    }

    public static class GenericMapPopulator<K, V, M extends Map<K, V>> implements Supplier<M> {
        private final M map;

        public GenericMapPopulator(M map) {
            this.map = Objects.requireNonNull(map, "No map provided");
        }

        public GenericMapPopulator<K, V, M> put(K k, V v) {
            map.put(k, v);
            return this;
        }

        public GenericMapPopulator<K, V, M> remove(K k) {
            map.remove(k);
            return this;
        }

        public GenericMapPopulator<K, V, M> putAll(Map<? extends K, ? extends V> other) {
            map.putAll(other);
            return this;
        }

        public GenericMapPopulator<K, V, M> clear() {
            map.clear();
            return this;
        }

        @Override
        public M get() {
            return map;
        }
    }

    public static class MapBuilder<K, V> extends GenericMapPopulator<K, V, Map<K, V>> {
        public MapBuilder() {
            super(new LinkedHashMap<>());
        }

        @Override
        public MapBuilder<K, V> put(K k, V v) {
            super.put(k, v);
            return this;
        }

        @Override
        public MapBuilder<K, V> remove(K k) {
            super.remove(k);
            return this;
        }

        @Override
        public MapBuilder<K, V> putAll(Map<? extends K, ? extends V> other) {
            super.putAll(other);
            return this;
        }

        @Override
        public MapBuilder<K, V> clear() {
            super.clear();
            return this;
        }

        public Map<K, V> build() {
            return get();
        }

        public Map<K, V> immutable() {
            return Collections.unmodifiableMap(build());
        }

        public static <K, V> MapBuilder<K, V> builder() {
            return new MapBuilder<>();
        }

    }

    public static class NavigableMapBuilder<K, V> extends GenericMapPopulator<K, V, NavigableMap<K, V>> {
        public NavigableMapBuilder(Comparator<? super K> comparator) {
            super(new TreeMap<>(Objects.requireNonNull(comparator, "No comparator provided")));
        }

        @Override
        public NavigableMapBuilder<K, V> put(K k, V v) {
            super.put(k, v);
            return this;
        }

        @Override
        public NavigableMapBuilder<K, V> remove(K k) {
            super.remove(k);
            return this;
        }

        @Override
        public NavigableMapBuilder<K, V> putAll(Map<? extends K, ? extends V> other) {
            super.putAll(other);
            return this;
        }

        @Override
        public NavigableMapBuilder<K, V> clear() {
            super.clear();
            return this;
        }

        public NavigableMap<K, V> build() {
            return get();
        }

        public NavigableMap<K, V> immutable() {
            return Collections.unmodifiableNavigableMap(build());
        }

        public static <K extends Comparable<? super K>, V> NavigableMapBuilder<K, V> builder() {
            return builder(Comparator.naturalOrder());
        }

        public static <K, V> NavigableMapBuilder<K, V> builder(Comparator<? super K> comparator) {
            return new NavigableMapBuilder<>(comparator);
        }
    }

    public static class EnumMapBuilder<K extends Enum<K>, V> extends GenericMapPopulator<K, V, Map<K, V>> {
        public EnumMapBuilder(Class<K> keyType) {
            super(new EnumMap<>(Objects.requireNonNull(keyType, "No enum class specified")));
        }

        @Override
        public EnumMapBuilder<K, V> put(K k, V v) {
            super.put(k, v);
            return this;
        }

        @Override
        public EnumMapBuilder<K, V> remove(K k) {
            super.remove(k);
            return this;
        }

        @Override
        public EnumMapBuilder<K, V> putAll(Map<? extends K, ? extends V> other) {
            super.putAll(other);
            return this;
        }

        @Override
        public EnumMapBuilder<K, V> clear() {
            super.clear();
            return this;
        }

        public Map<K, V> build() {
            return get();
        }

        public Map<K, V> immutable() {
            return Collections.unmodifiableMap(build());
        }

        public static <K extends Enum<K>, V> EnumMapBuilder<K, V> builder(Class<K> keyType) {
            return new EnumMapBuilder<>(keyType);
        }
    }
}
