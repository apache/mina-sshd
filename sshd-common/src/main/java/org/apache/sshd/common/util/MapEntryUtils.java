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

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;
import java.util.stream.Collectors;

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

    @SuppressWarnings("rawtypes")
    private static final Supplier CASE_INSENSITIVE_MAP_FACTORY = () -> new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

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
            if (v == null) {
                return remove(k);
            }
            map.put(Objects.requireNonNull(k, "No key provided"), v);
            return this;
        }

        public GenericMapPopulator<K, V, M> remove(K k) {
            map.remove(k);
            return this;
        }

        public GenericMapPopulator<K, V, M> putAll(Map<? extends K, ? extends V> other) {
            if (isNotEmpty(other)) {
                other.forEach(this::put);
            }
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

    public static int size(Map<?, ?> m) {
        return (m == null) ? 0 : m.size();
    }

    public static boolean isEmpty(Map<?, ?> m) {
        return size(m) <= 0;
    }

    public static boolean isNotEmpty(Map<?, ?> m) {
        return !isEmpty(m);
    }

    /**
     * @param  <V> Type of mapped value
     * @return     A {@link Supplier} that returns a <U>new</U> {@link NavigableMap} whenever its {@code get()} method
     *             is invoked
     */
    @SuppressWarnings("unchecked")
    public static <V> Supplier<NavigableMap<String, V>> caseInsensitiveMap() {
        return CASE_INSENSITIVE_MAP_FACTORY;
    }

    /**
     * Flips between keys and values of an input map
     *
     * @param  <K>                      Original map key type
     * @param  <V>                      Original map value type
     * @param  <M>                      Flipped map type
     * @param  map                      The original map to flip
     * @param  mapCreator               The creator of the target map
     * @param  allowDuplicates          Whether to ignore duplicates on flip
     * @return                          The flipped map result
     * @throws IllegalArgumentException if <tt>allowDuplicates</tt> is {@code false} and a duplicate value found in the
     *                                  original map.
     */
    public static <K, V, M extends Map<V, K>> M flipMap(
            Map<? extends K, ? extends V> map, Supplier<? extends M> mapCreator, boolean allowDuplicates) {
        M result = Objects.requireNonNull(mapCreator.get(), "No map created");
        map.forEach((key, value) -> {
            K prev = result.put(value, key);
            if ((prev != null) && (!allowDuplicates)) {
                ValidateUtils.throwIllegalArgumentException("Multiple values for key=%s: current=%s, previous=%s", value, key,
                        prev);
            }
        });

        return result;
    }

    @SafeVarargs
    public static <K, V, M extends Map<K, V>> M mapValues(
            Function<? super V, ? extends K> keyMapper, Supplier<? extends M> mapCreator, V... values) {
        return mapValues(keyMapper, mapCreator, GenericUtils.isEmpty(values) ? Collections.emptyList() : Arrays.asList(values));
    }

    /**
     * Creates a map out of a group of values
     *
     * @param  <K>        The key type
     * @param  <V>        The value type
     * @param  <M>        The result {@link Map} type
     * @param  keyMapper  The {@link Function} that generates a key for a given value. If the returned key is
     *                    {@code null} then the value is not mapped
     * @param  mapCreator The {@link Supplier} used to create/retrieve the result map - provided non-empty group of
     *                    values
     * @param  values     The values to be mapped
     * @return            The resulting {@link Map} - <B>Note:</B> no validation is made to ensure that 2 (or more)
     *                    values are not mapped to the same key
     */
    public static <K, V, M extends Map<K, V>> M mapValues(
            Function<? super V, ? extends K> keyMapper,
            Supplier<? extends M> mapCreator,
            Collection<? extends V> values) {
        M map = mapCreator.get();
        for (V v : values) {
            K k = keyMapper.apply(v);
            if (k == null) {
                continue; // debug breakpoint
            }
            map.put(k, v);
        }

        return map;
    }

    public static <T, K, U> NavigableMap<K, U> toSortedMap(
            Iterable<? extends T> values, Function<? super T, ? extends K> keyMapper,
            Function<? super T, ? extends U> valueMapper, Comparator<? super K> comparator) {
        return GenericUtils.stream(values).collect(toSortedMap(keyMapper, valueMapper, comparator));
    }

    public static <T, K, U> Collector<T, ?, NavigableMap<K, U>> toSortedMap(
            Function<? super T, ? extends K> keyMapper,
            Function<? super T, ? extends U> valueMapper,
            Comparator<? super K> comparator) {
        return Collectors.toMap(keyMapper, valueMapper, throwingMerger(), () -> new TreeMap<>(comparator));
    }

    public static <T> BinaryOperator<T> throwingMerger() {
        return (u, v) -> {
            throw new IllegalStateException(String.format("Duplicate key %s", u));
        };
    }
}
