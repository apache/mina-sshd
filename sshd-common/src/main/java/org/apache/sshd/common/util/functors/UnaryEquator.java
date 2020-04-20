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

package org.apache.sshd.common.util.functors;

import java.util.Comparator;
import java.util.Objects;
import java.util.function.BiPredicate;

import org.apache.sshd.common.util.GenericUtils;

/**
 * Checks equality between 2 entities of same type
 * 
 * @param  <T> Type of compared entity
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface UnaryEquator<T> extends BiPredicate<T, T> {
    /**
     * Returns a composed equator that represents a short-circuiting logical AND of this equator and another. When
     * evaluating the composed equator, if this equator is {@code false}, then the {@code other} equator is not
     * evaluated.
     *
     * @param  other The other (never {@code null} equator
     * @return       The compound equator
     */
    default UnaryEquator<T> and(UnaryEquator<? super T> other) {
        Objects.requireNonNull(other, "No other equator to compose");
        return (t1, t2) -> this.test(t1, t2) && other.test(t1, t2);
    }

    /**
     * Returns a composed equator that represents a short-circuiting logical AND of this equator and another. When
     * evaluating the composed equator, if this equator is {@code true}, then the {@code other} equator is not
     * evaluated.
     *
     * @param  other The other (never {@code null} equator
     * @return       The compound equator
     */
    default UnaryEquator<T> or(UnaryEquator<? super T> other) {
        Objects.requireNonNull(other, "No other equator to compose");
        return (t1, t2) -> this.test(t1, t2) || other.test(t1, t2);
    }

    /**
     * @return an equator that represents the logical negation of this one
     */
    @Override
    default UnaryEquator<T> negate() {
        return (t1, t2) -> !this.test(t1, t2);
    }

    /**
     * @param  <T> Type of entity
     * @return     The default equality checker
     * @see        Objects#equals(Object, Object)
     */
    static <T> UnaryEquator<T> defaultEquality() {
        return Objects::equals;
    }

    /**
     * @param  <T> Type of entity
     * @return     An equator that checks reference equality
     * @see        GenericUtils#isSameReference(Object, Object)
     */
    static <T> UnaryEquator<T> referenceEquality() {
        return GenericUtils::isSameReference;
    }

    /**
     * Converts a {@link Comparator} into a {@link UnaryEquator} that returns {@code true} if the comparator returns
     * zero
     *
     * @param  <T> Type of entity
     * @param  c   The (never {@code null}) comparator
     * @return     The equivalent equator
     */
    static <T> UnaryEquator<T> comparing(Comparator<? super T> c) {
        Objects.requireNonNull(c, "No comparator");
        return (o1, o2) -> c.compare(o1, o2) == 0;
    }

    /**
     * @param  <T> Type of evaluated entity
     * @return     A {@link UnaryEquator} that returns always {@code true}
     * @see        <A HREF="https://en.wikipedia.org/wiki/Tee_(symbol)">verum</A>
     */
    static <T> UnaryEquator<T> verum() {
        return (o1, o2) -> true;
    }

    /**
     * @param  <T> Type of evaluated entity
     * @return     A {@link UnaryEquator} that returns always {@code false}
     * @see        <A HREF="https://en.wikipedia.org/wiki/Up_tack">falsum</A>
     */
    static <T> UnaryEquator<T> falsum() {
        return (o1, o2) -> false;
    }
}
