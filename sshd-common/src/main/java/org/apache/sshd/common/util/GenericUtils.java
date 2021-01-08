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

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.UndeclaredThrowableException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BinaryOperator;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import javax.management.MBeanException;
import javax.management.ReflectionException;

import org.apache.sshd.common.util.functors.UnaryEquator;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class GenericUtils {

    public static final byte[] EMPTY_BYTE_ARRAY = {};
    public static final char[] EMPTY_CHAR_ARRAY = {};
    public static final String[] EMPTY_STRING_ARRAY = {};
    public static final Object[] EMPTY_OBJECT_ARRAY = {};
    public static final boolean[] EMPTY_BOOLEAN_ARRAY = {};

    /**
     * A value indicating a {@code null} value - to be used as a placeholder where {@code null}s are not allowed
     */
    public static final Object NULL = new Object();

    /**
     * The complement of {@link String#CASE_INSENSITIVE_ORDER}
     */
    public static final Comparator<String> CASE_SENSITIVE_ORDER = (s1, s2) -> {
        if (s1 == s2) {
            return 0;
        } else {
            return s1.compareTo(s2);
        }
    };

    public static final String QUOTES = "\"'";

    @SuppressWarnings("rawtypes")
    private static final Supplier CASE_INSENSITIVE_MAP_FACTORY = () -> new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    private GenericUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    public static String trimToEmpty(String s) {
        if (s == null) {
            return "";
        } else {
            return s.trim();
        }
    }

    public static String replaceWhitespaceAndTrim(String s) {
        if (s != null) {
            s = s.replace('\t', ' ');
        }

        return trimToEmpty(s);
    }

    /**
     * <p>
     * Replace a String with another String inside a larger String, for the first <code>max</code> values of the search
     * String.
     * </p>
     *
     * <p>
     * A {@code null} reference passed to this method is a no-op.
     * </p>
     *
     * @param  text text to search and replace in
     * @param  repl String to search for
     * @param  with String to replace with
     * @param  max  maximum number of values to replace, or <code>-1</code> if no maximum
     * @return      the text with any replacements processed
     * @author      Arnout J. Kuiper <a href="mailto:ajkuiper@wxs.nl">ajkuiper@wxs.nl</a>
     * @author      Magesh Umasankar
     * @author      <a href="mailto:bruce@callenish.com">Bruce Atherton</a>
     * @author      <a href="mailto:levylambert@tiscali-dsl.de">Antoine Levy-Lambert</a>
     */
    @SuppressWarnings("PMD.AssignmentInOperand")
    public static String replace(String text, String repl, String with, int max) {
        if ((text == null) || (repl == null) || (with == null) || (repl.length() == 0)) {
            return text;
        }

        int start = 0;
        StringBuilder buf = new StringBuilder(text.length());
        for (int end = text.indexOf(repl, start); end != -1; end = text.indexOf(repl, start)) {
            buf.append(text.substring(start, end)).append(with);
            start = end + repl.length();

            if (--max == 0) {
                break;
            }
        }
        buf.append(text.substring(start));
        return buf.toString();
    }

    /**
     * @param  s The {@link String} value to calculate the hash code on - may be {@code null}/empty in which case a
     *           value of zero is returned
     * @return   The calculated hash code
     * @see      #hashCode(String, Boolean)
     */
    public static int hashCode(String s) {
        return hashCode(s, null);
    }

    /**
     * @param  s            The {@link String} value to calculate the hash code on - may be {@code null}/empty in which
     *                      case a value of zero is returned
     * @param  useUppercase Whether to convert the string to uppercase, lowercase or not at all:
     *                      <UL>
     *                      <LI>{@code null} - no conversion</LI>
     *                      <LI>{@link Boolean#TRUE} - get hash code of uppercase</LI>
     *                      <LI>{@link Boolean#FALSE} - get hash code of lowercase</LI>
     *                      </UL>
     * @return              The calculated hash code
     */
    public static int hashCode(String s, Boolean useUppercase) {
        if (isEmpty(s)) {
            return 0;
        } else if (useUppercase == null) {
            return s.hashCode();
        } else if (useUppercase.booleanValue()) {
            return s.toUpperCase().hashCode();
        } else {
            return s.toLowerCase().hashCode();
        }
    }

    public static int safeCompare(String s1, String s2, boolean caseSensitive) {
        if (isSameReference(s1, s2)) {
            return 0;
        } else if (s1 == null) {
            return +1; // push null(s) to end
        } else if (s2 == null) {
            return -1; // push null(s) to end
        } else if (caseSensitive) {
            return s1.compareTo(s2);
        } else {
            return s1.compareToIgnoreCase(s2);
        }
    }

    public static <T> boolean isSameReference(T o1, T o2) {
        return o1 == o2;
    }

    public static int length(CharSequence cs) {
        return cs == null ? 0 : cs.length();
    }

    public static boolean isEmpty(CharSequence cs) {
        return length(cs) <= 0;
    }

    public static boolean isNotEmpty(CharSequence cs) {
        return !isEmpty(cs);
    }

    public static int indexOf(CharSequence cs, char c) {
        int len = length(cs);
        for (int pos = 0; pos < len; pos++) {
            char ch = cs.charAt(pos);
            if (ch == c) {
                return pos;
            }
        }

        return -1;
    }

    public static int lastIndexOf(CharSequence cs, char c) {
        int len = length(cs);
        for (int pos = len - 1; pos >= 0; pos--) {
            char ch = cs.charAt(pos);
            if (ch == c) {
                return pos;
            }
        }

        return -1;
    }

    // a List would be better, but we want to be compatible with String.split(...)
    public static String[] split(String s, char ch) {
        if (isEmpty(s)) {
            return EMPTY_STRING_ARRAY;
        }

        int lastPos = 0;
        int curPos = s.indexOf(ch);
        if (curPos < 0) {
            return new String[] { s };
        }

        Collection<String> values = new LinkedList<>();
        do {
            String v = s.substring(lastPos, curPos);
            values.add(v);

            // skip separator
            lastPos = curPos + 1;
            if (lastPos >= s.length()) {
                break;
            }

            curPos = s.indexOf(ch, lastPos);
            if (curPos < lastPos) {
                break; // no more separators
            }
        } while (curPos < s.length());

        // check if any leftovers
        if (lastPos < s.length()) {
            String v = s.substring(lastPos);
            values.add(v);
        }

        return values.toArray(new String[values.size()]);
    }

    public static <T> String join(T[] values, char ch) {
        return join(isEmpty(values) ? Collections.<T> emptyList() : Arrays.asList(values), ch);
    }

    public static String join(Iterable<?> iter, char ch) {
        return join((iter == null) ? null : iter.iterator(), ch);
    }

    public static String join(Iterator<?> iter, char ch) {
        if ((iter == null) || (!iter.hasNext())) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        do { // we already asked hasNext...
            Object o = iter.next();
            if (sb.length() > 0) {
                sb.append(ch);
            }
            sb.append(Objects.toString(o));
        } while (iter.hasNext());

        return sb.toString();
    }

    public static <T> String join(T[] values, CharSequence sep) {
        return join(isEmpty(values) ? Collections.<T> emptyList() : Arrays.asList(values), sep);
    }

    public static String join(Iterable<?> iter, CharSequence sep) {
        return join((iter == null) ? null : iter.iterator(), sep);
    }

    public static String join(Iterator<?> iter, CharSequence sep) {
        if ((iter == null) || (!iter.hasNext())) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        do { // we already asked hasNext...
            Object o = iter.next();
            if (sb.length() > 0) {
                sb.append(sep);
            }
            sb.append(Objects.toString(o));
        } while (iter.hasNext());

        return sb.toString();
    }

    public static int size(Collection<?> c) {
        return (c == null) ? 0 : c.size();
    }

    public static boolean isEmpty(Collection<?> c) {
        return size(c) <= 0;
    }

    public static boolean isNotEmpty(Collection<?> c) {
        return !isEmpty(c);
    }

    /**
     *
     * @param  <T> Generic element type
     * @param  c1  First collection
     * @param  c2  Second collection
     * @return     {@code true} if the following holds:
     *             <UL>
     *             <LI>Same size - <B>Note:</B> {@code null} collections are consider equal to empty ones</LI>
     *
     *             <LI>First collection contains all elements of second one and vice versa</LI>
     *             </UL>
     */
    public static <T> boolean equals(Collection<T> c1, Collection<T> c2) {
        if (isEmpty(c1)) {
            return isEmpty(c2);
        } else if (isEmpty(c2)) {
            return false;
        }

        return (c1.size() == c2.size())
                && c1.containsAll(c2)
                && c2.containsAll(c1);
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

    @SafeVarargs
    public static <T> int length(T... a) {
        return (a == null) ? 0 : a.length;
    }

    public static <T> boolean isEmpty(Iterable<? extends T> iter) {
        if (iter == null) {
            return true;
        } else if (iter instanceof Collection<?>) {
            return isEmpty((Collection<?>) iter);
        } else {
            return isEmpty(iter.iterator());
        }
    }

    public static <T> boolean isNotEmpty(Iterable<? extends T> iter) {
        return !isEmpty(iter);
    }

    public static <T> boolean isEmpty(Iterator<? extends T> iter) {
        return (iter == null) || (!iter.hasNext());
    }

    public static <T> boolean isNotEmpty(Iterator<? extends T> iter) {
        return !isEmpty(iter);
    }

    @SafeVarargs
    public static <T> boolean isEmpty(T... a) {
        return length(a) <= 0;
    }

    public static int length(char[] chars) {
        return (chars == null) ? 0 : chars.length;
    }

    public static boolean isEmpty(char[] chars) {
        return length(chars) <= 0;
    }

    /**
     * Compares 2 character arrays - <B>Note:</B> {@code null} and empty are considered <U>equal</U>
     *
     * @param  c1 1st array
     * @param  c2 2nd array
     * @return    Negative is 1st array comes first in lexicographical order, positive if 2nd array comes first and zero
     *            if equal
     */
    public static int compare(char[] c1, char[] c2) {
        int l1 = length(c1);
        int l2 = length(c2);
        int cmpLen = Math.min(l1, l2);
        for (int index = 0; index < cmpLen; index++) {
            char c11 = c1[index];
            char c22 = c2[index];
            int nRes = Character.compare(c11, c22);
            if (nRes != 0) {
                return nRes;
            }
        }

        int nRes = Integer.compare(l1, l2);
        if (nRes != 0) {
            return nRes;
        }

        return 0;
    }

    @SafeVarargs // there is no EnumSet.of(...) so we have to provide our own
    public static <E extends Enum<E>> Set<E> of(E... values) {
        return of(isEmpty(values) ? Collections.emptySet() : Arrays.asList(values));
    }

    public static <E extends Enum<E>> Set<E> of(Collection<? extends E> values) {
        if (isEmpty(values)) {
            return Collections.emptySet();
        }

        Set<E> result = null;
        for (E v : values) {
            /*
             * A trick to compensate for the fact that we do not have the enum Class to invoke EnumSet.noneOf
             */
            if (result == null) {
                result = EnumSet.of(v);
            } else {
                result.add(v);
            }
        }

        return result;
    }

    public static <T> int findFirstDifferentValueIndex(List<? extends T> c1, List<? extends T> c2) {
        return findFirstDifferentValueIndex(c1, c2, UnaryEquator.defaultEquality());
    }

    public static <T> int findFirstDifferentValueIndex(
            List<? extends T> c1, List<? extends T> c2, UnaryEquator<? super T> equator) {
        Objects.requireNonNull(equator, "No equator provided");

        int l1 = size(c1);
        int l2 = size(c2);
        for (int index = 0, count = Math.min(l1, l2); index < count; index++) {
            T v1 = c1.get(index);
            T v2 = c2.get(index);
            if (!equator.test(v1, v2)) {
                return index;
            }
        }

        // all common length items are equal - check length
        if (l1 < l2) {
            return l1;
        } else if (l2 < l1) {
            return l2;
        } else {
            return -1;
        }
    }

    public static <T> int findFirstDifferentValueIndex(Iterable<? extends T> c1, Iterable<? extends T> c2) {
        return findFirstDifferentValueIndex(c1, c2, UnaryEquator.defaultEquality());
    }

    public static <T> int findFirstDifferentValueIndex(
            Iterable<? extends T> c1, Iterable<? extends T> c2, UnaryEquator<? super T> equator) {
        return findFirstDifferentValueIndex(iteratorOf(c1), iteratorOf(c2), equator);
    }

    public static <T> int findFirstDifferentValueIndex(Iterator<? extends T> i1, Iterator<? extends T> i2) {
        return findFirstDifferentValueIndex(i1, i2, UnaryEquator.defaultEquality());
    }

    public static <T> int findFirstDifferentValueIndex(
            Iterator<? extends T> i1, Iterator<? extends T> i2, UnaryEquator<? super T> equator) {
        Objects.requireNonNull(equator, "No equator provided");

        i1 = iteratorOf(i1);
        i2 = iteratorOf(i2);
        for (int index = 0;; index++) {
            if (i1.hasNext()) {
                if (i2.hasNext()) {
                    T v1 = i1.next();
                    T v2 = i2.next();
                    if (!equator.test(v1, v2)) {
                        return index;
                    }
                } else {
                    return index;
                }
            } else if (i2.hasNext()) {
                return index;
            } else {
                return -1; // neither has a next value - both exhausted at the same time
            }
        }
    }

    public static <T> boolean containsAny(
            Collection<? extends T> coll, Iterable<? extends T> values) {
        if (isEmpty(coll)) {
            return false;
        }

        for (T v : values) {
            if (coll.contains(v)) {
                return true;
            }
        }

        return false;
    }

    public static <T> void forEach(
            Iterable<? extends T> values, Consumer<? super T> consumer) {
        if (isNotEmpty(values)) {
            values.forEach(consumer);
        }
    }

    public static <T, U> List<U> map(
            Collection<? extends T> values, Function<? super T, ? extends U> mapper) {
        return stream(values).map(mapper).collect(Collectors.toList());
    }

    public static <T, U> NavigableSet<U> mapSort(
            Collection<? extends T> values, Function<? super T, ? extends U> mapper, Comparator<? super U> comparator) {
        return stream(values).map(mapper).collect(toSortedSet(comparator));
    }

    public static <T, K, U> NavigableMap<K, U> toSortedMap(
            Iterable<? extends T> values, Function<? super T, ? extends K> keyMapper,
            Function<? super T, ? extends U> valueMapper, Comparator<? super K> comparator) {
        return stream(values).collect(toSortedMap(keyMapper, valueMapper, comparator));
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

    public static <T> Collector<T, ?, NavigableSet<T>> toSortedSet(Comparator<? super T> comparator) {
        return Collectors.toCollection(() -> new TreeSet<>(comparator));
    }

    public static <T> Stream<T> stream(Iterable<T> values) {
        if (isEmpty(values)) {
            return Stream.empty();
        } else if (values instanceof Collection<?>) {
            return ((Collection<T>) values).stream();
        } else {
            return StreamSupport.stream(values.spliterator(), false);
        }
    }

    @SafeVarargs
    public static <T> List<T> unmodifiableList(T... values) {
        return unmodifiableList(asList(values));
    }

    public static <T> List<T> unmodifiableList(Collection<? extends T> values) {
        if (isEmpty(values)) {
            return Collections.emptyList();
        } else {
            return Collections.unmodifiableList(new ArrayList<>(values));
        }
    }

    public static <T> List<T> unmodifiableList(Stream<T> values) {
        return unmodifiableList(values.collect(Collectors.toList()));
    }

    @SafeVarargs
    public static <T> List<T> asList(T... values) {
        return isEmpty(values) ? Collections.emptyList() : Arrays.asList(values);
    }

    @SafeVarargs
    public static <T> Set<T> asSet(T... values) {
        return new HashSet<>(asList(values));
    }

    @SafeVarargs
    public static <V extends Comparable<V>> NavigableSet<V> asSortedSet(V... values) {
        return asSortedSet(Comparator.naturalOrder(), values);
    }

    public static <V extends Comparable<V>> NavigableSet<V> asSortedSet(Collection<? extends V> values) {
        return asSortedSet(Comparator.naturalOrder(), values);
    }

    /**
     * @param  <V>    The element type
     * @param  comp   The (non-{@code null}) {@link Comparator} to use
     * @param  values The values to be added (ignored if {@code null})
     * @return        A {@link NavigableSet} containing the values (if any) sorted using the provided comparator
     */
    @SafeVarargs
    public static <V> NavigableSet<V> asSortedSet(Comparator<? super V> comp, V... values) {
        return asSortedSet(comp, isEmpty(values) ? Collections.emptyList() : Arrays.asList(values));
    }

    /**
     * @param  <V>    The element type
     * @param  comp   The (non-{@code null}) {@link Comparator} to use
     * @param  values The values to be added (ignored if {@code null}/empty)
     * @return        A {@link NavigableSet} containing the values (if any) sorted using the provided comparator
     */
    public static <V> NavigableSet<V> asSortedSet(
            Comparator<? super V> comp, Collection<? extends V> values) {
        NavigableSet<V> set = new TreeSet<>(Objects.requireNonNull(comp, "No comparator"));
        if (size(values) > 0) {
            set.addAll(values);
        }
        return set;
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
        return mapValues(keyMapper, mapCreator, isEmpty(values) ? Collections.emptyList() : Arrays.asList(values));
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

    @SafeVarargs
    public static <T> T findFirstMatchingMember(Predicate<? super T> acceptor, T... values) {
        return findFirstMatchingMember(acceptor,
                isEmpty(values) ? Collections.emptyList() : Arrays.asList(values));
    }

    public static <T> T findFirstMatchingMember(
            Predicate<? super T> acceptor, Collection<? extends T> values) {
        List<T> matches = selectMatchingMembers(acceptor, values);
        return GenericUtils.isEmpty(matches) ? null : matches.get(0);
    }

    /**
     * Returns a list of all the values that were accepted by a predicate
     *
     * @param  <T>      The type of value being evaluated
     * @param  acceptor The {@link Predicate} to consult whether a member is selected
     * @param  values   The values to be scanned
     * @return          A {@link List} of all the values that were accepted by the predicate
     */
    @SafeVarargs
    public static <T> List<T> selectMatchingMembers(Predicate<? super T> acceptor, T... values) {
        return selectMatchingMembers(acceptor,
                isEmpty(values) ? Collections.emptyList() : Arrays.asList(values));
    }

    /**
     * Returns a list of all the values that were accepted by a predicate
     *
     * @param  <T>      The type of value being evaluated
     * @param  acceptor The {@link Predicate} to consult whether a member is selected
     * @param  values   The values to be scanned
     * @return          A {@link List} of all the values that were accepted by the predicate
     */
    public static <T> List<T> selectMatchingMembers(
            Predicate<? super T> acceptor, Collection<? extends T> values) {
        return GenericUtils.stream(values)
                .filter(acceptor)
                .collect(Collectors.toList());
    }

    /**
     * @param  s The {@link CharSequence} to be checked
     * @return   If the sequence contains any of the {@link #QUOTES} on <U>both</U> ends, then they are stripped,
     *           otherwise nothing is done
     * @see      #stripDelimiters(CharSequence, char)
     */
    public static CharSequence stripQuotes(CharSequence s) {
        if (isEmpty(s)) {
            return s;
        }

        for (int index = 0; index < QUOTES.length(); index++) {
            char delim = QUOTES.charAt(index);
            CharSequence v = stripDelimiters(s, delim);
            if (v != s) { // if stripped one don't continue
                return v;
            }
        }

        return s;
    }

    /**
     * @param  s     The {@link CharSequence} to be checked
     * @param  delim The expected delimiter
     * @return       If the sequence contains the delimiter on <U>both</U> ends, then it is are stripped, otherwise
     *               nothing is done
     */
    public static CharSequence stripDelimiters(CharSequence s, char delim) {
        if (isEmpty(s) || (s.length() < 2)) {
            return s;
        }

        int lastPos = s.length() - 1;
        if ((s.charAt(0) != delim) || (s.charAt(lastPos) != delim)) {
            return s;
        } else {
            return s.subSequence(1, lastPos);
        }
    }

    public static RuntimeException toRuntimeException(Throwable t) {
        return toRuntimeException(t, true);
    }

    /**
     * Converts a thrown generic exception to a {@link RuntimeException}
     *
     * @param  t             The original thrown exception
     * @param  peelThrowable Whether to determine the root cause by &quot;peeling&quot; any enclosing exceptions
     * @return               The thrown cause if already a runtime exception, otherwise a runtime exception of the
     *                       resolved exception as its cause
     * @see                  #peelException(Throwable)
     */
    public static RuntimeException toRuntimeException(Throwable t, boolean peelThrowable) {
        Throwable e = peelThrowable ? peelException(t) : t;
        if (e instanceof RuntimeException) {
            return (RuntimeException) e;
        }

        return new RuntimeException(e);
    }

    /**
     * Attempts to get to the &quot;effective&quot; exception being thrown, by taking care of some known exceptions that
     * wrap the original thrown one.
     *
     * @param  t The original {@link Throwable} - ignored if {@code null}
     * @return   The effective exception - same as input if not a wrapper
     */
    public static Throwable peelException(Throwable t) {
        // NOTE: check order is important - e.g., InvocationTargetException extends ReflectiveOperationException
        if (t == null) {
            return t;
        } else if (t instanceof UndeclaredThrowableException) {
            Throwable wrapped = ((UndeclaredThrowableException) t).getUndeclaredThrowable();
            // according to the Javadoc it may be null, in which case 'getCause'
            // might contain the information we need
            if (wrapped != null) {
                return peelException(wrapped);
            }

            wrapped = t.getCause();
            if (wrapped != t) { // make sure it is a real cause
                return peelException(wrapped);
            }
        } else if (t instanceof InvocationTargetException) {
            Throwable target = ((InvocationTargetException) t).getTargetException();
            if (target != null) {
                return peelException(target);
            }
        } else if (t instanceof ReflectionException) {
            Throwable target = ((ReflectionException) t).getTargetException();
            if (target != null) {
                return peelException(target);
            }
        } else if (t instanceof ExecutionException) {
            Throwable wrapped = resolveExceptionCause(t);
            if (wrapped != null) {
                return peelException(wrapped);
            }
        } else if (t instanceof MBeanException) {
            Throwable target = ((MBeanException) t).getTargetException();
            if (target != null) {
                return peelException(target);
            }
        }

        return t; // no special handling required or available
    }

    /**
     * @param  t The original {@link Throwable} - ignored if {@code null}
     * @return   If {@link Throwable#getCause()} is non-{@code null} then the cause, otherwise the original exception -
     *           {@code null} if the original exception was {@code null}
     */
    public static Throwable resolveExceptionCause(Throwable t) {
        if (t == null) {
            return t;
        }

        Throwable c = t.getCause();
        if (c == null) {
            return t;
        } else {
            return c;
        }
    }

    /**
     * Used to &quot;accumulate&quot; exceptions of the <U>same type</U>. If the current exception is {@code null} then
     * the new one becomes the current, otherwise the new one is added as a <U>suppressed</U> exception to the current
     * one
     *
     * @param  <T>     The exception type
     * @param  current The current exception
     * @param  extra   The extra/new exception
     * @return         The resolved exception
     * @see            Throwable#addSuppressed(Throwable)
     */
    public static <T extends Throwable> T accumulateException(T current, T extra) {
        if (current == null) {
            return extra;
        }

        if ((extra == null) || (extra == current)) {
            return current;
        }

        current.addSuppressed(extra);
        return current;
    }

    public static void rethrowAsIoException(Throwable e) throws IOException {
        if (e instanceof IOException) {
            throw (IOException) e;
        } else if (e instanceof RuntimeException) {
            throw (RuntimeException) e;
        } else if (e instanceof Error) {
            throw (Error) e;
        } else {
            throw new IOException(e);
        }
    }

    /**
     * Wraps a value into a {@link Supplier}
     *
     * @param  <T>   Type of value being supplied
     * @param  value The value to be supplied
     * @return       The supplier wrapper
     */
    public static <T> Supplier<T> supplierOf(T value) {
        return () -> value;
    }

    /**
     * Resolves to an always non-{@code null} iterator
     *
     * @param  <T>      Type of value being iterated
     * @param  iterable The {@link Iterable} instance
     * @return          A non-{@code null} iterator which may be empty if no iterable instance or no iterator returned
     *                  from it
     * @see             #iteratorOf(Iterator)
     */
    public static <T> Iterator<T> iteratorOf(Iterable<T> iterable) {
        return iteratorOf((iterable == null) ? null : iterable.iterator());
    }

    /**
     * @param  <B> Generic base class
     * @param  <D> Generic child class
     * @return     An identity {@link Function} that returns its input child class as a base class
     */
    public static <B, D extends B> Function<D, B> downcast() {
        return t -> t;
    }

    /**
     * Returns the first element in iterable - it has some optimization for {@link List}-s {@link Deque}-s and
     * {@link SortedSet}s.
     *
     * @param  <T> Type of element
     * @param  it  The {@link Iterable} instance - ignored if {@code null}/empty
     * @return     first element by iteration or {@code null} if none available
     */
    public static <T> T head(Iterable<? extends T> it) {
        if (it == null) {
            return null;
        } else if (it instanceof Deque<?>) { // check before (!) instanceof List since LinkedList implements List
            Deque<? extends T> l = (Deque<? extends T>) it;
            return (l.size() > 0) ? l.getFirst() : null;
        } else if (it instanceof List<?>) {
            List<? extends T> l = (List<? extends T>) it;
            return (l.size() > 0) ? l.get(0) : null;
        } else if (it instanceof SortedSet<?>) {
            SortedSet<? extends T> s = (SortedSet<? extends T>) it;
            return (s.size() > 0) ? s.first() : null;
        } else {
            Iterator<? extends T> iter = it.iterator();
            return ((iter == null) || (!iter.hasNext())) ? null : iter.next();
        }
    }

    /**
     * Resolves to an always non-{@code null} iterator
     *
     * @param  <T>  Type of value being iterated
     * @param  iter The {@link Iterator} instance
     * @return      A non-{@code null} iterator which may be empty if no iterator instance
     * @see         Collections#emptyIterator()
     */
    public static <T> Iterator<T> iteratorOf(Iterator<T> iter) {
        return (iter == null) ? Collections.emptyIterator() : iter;
    }

    public static <U, V> Iterable<V> wrapIterable(
            Iterable<? extends U> iter, Function<? super U, ? extends V> mapper) {
        return () -> wrapIterator(iter, mapper);
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    public static <U, V> Iterator<V> wrapIterator(
            Iterable<? extends U> iter, Function<? super U, ? extends V> mapper) {
        return (Iterator) stream(iter).map(mapper).iterator();
    }

    public static <U, V> Iterator<V> wrapIterator(
            Iterator<? extends U> iter, Function<? super U, ? extends V> mapper) {
        Iterator<? extends U> iterator = iteratorOf(iter);
        return new Iterator<V>() {
            @Override
            public boolean hasNext() {
                return iterator.hasNext();
            }

            @Override
            public V next() {
                U value = iterator.next();
                return mapper.apply(value);
            }
        };
    }

    /**
     * @param  <T>    Generic return type
     * @param  values The source values - ignored if {@code null}
     * @param  type   The (never @code null) type of values to select - any value whose type is assignable to this type
     *                will be selected by the iterator.
     * @return        The first value that matches the specified type - {@code null} if none found
     */
    public static <T> T selectNextMatchingValue(Iterator<?> values, Class<T> type) {
        Objects.requireNonNull(type, "No type selector specified");
        if (values == null) {
            return null;
        }

        while (values.hasNext()) {
            Object o = values.next();
            if (o == null) {
                continue;
            }

            Class<?> t = o.getClass();
            if (type.isAssignableFrom(t)) {
                return type.cast(o);
            }
        }

        return null;
    }

    /**
     * Wraps a group of {@link Supplier}s of {@link Iterable} instances into a &quot;unified&quot; {@link Iterable} of
     * their values, in the same order as the suppliers - i.e., once the values from a specific supplier are exhausted,
     * the next one is consulted, and so on, until all suppliers have been consulted
     *
     * @param  <T>       Type of value being iterated
     * @param  providers The providers - ignored if {@code null} (i.e., return an empty iterable instance)
     * @return           The wrapping instance
     */
    public static <T> Iterable<T> multiIterableSuppliers(
            Iterable<? extends Supplier<? extends Iterable<? extends T>>> providers) {
        return () -> stream(providers).<T> flatMap(s -> stream(s.get())).map(Function.identity()).iterator();
    }

    /**
     * The delegate Suppliers get() method is called exactly once and the result is cached.
     *
     * @param  <T>      Generic type of supplied value
     * @param  delegate The actual Supplier
     * @return          The memoized Supplier
     */
    public static <T> Supplier<T> memoizeLock(Supplier<? extends T> delegate) {
        AtomicReference<T> value = new AtomicReference<>();
        return () -> {
            T val = value.get();
            if (val == null) {
                synchronized (value) {
                    val = value.get();
                    if (val == null) {
                        val = Objects.requireNonNull(delegate.get());
                        value.set(val);
                    }
                }
            }
            return val;
        };
    }

    /**
     * Check if a duration is positive
     *
     * @param  d the duration
     * @return   <code>true</code> if the duration is greater than zero
     */
    public static boolean isPositive(Duration d) {
        return !isNegativeOrNull(d);
    }

    /**
     * Check if a duration is negative or zero
     *
     * @param  d the duration
     * @return   <code>true</code> if the duration is negative or zero
     */
    public static boolean isNegativeOrNull(Duration d) {
        return d.isNegative() || d.isZero();
    }
}
