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

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.temporal.Temporal;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class LazyMatchingTypeIteratorTest extends JUnitTestSupport {
    public LazyMatchingTypeIteratorTest() {
        super();
    }

    @Test
    public void testLazySelectMatchingTypes() {
        Collection<String> strings = Arrays.asList(
                getCurrentTestName(),
                getClass().getSimpleName(),
                getClass().getPackage().getName());
        Collection<Temporal> times = Arrays.asList(
                LocalDateTime.now(),
                LocalTime.now(),
                LocalDate.now());
        List<Object> values = Stream.concat(strings.stream(), times.stream()).collect(Collectors.toList());
        AtomicInteger matchCount = new AtomicInteger(0);
        for (int index = 1, count = values.size(); index <= count; index++) {
            Collections.shuffle(values);
            Class<?> type = ((index & 0x01) == 0) ? String.class : Temporal.class;
            Iterator<?> lazy = LazyMatchingTypeIterator.lazySelectMatchingTypes(
                    new Iterator<Object>() {
                        private final Iterator<?> iter = values.iterator();

                        {
                            matchCount.set(0);
                        }

                        @Override
                        public boolean hasNext() {
                            return iter.hasNext();
                        }

                        @Override
                        public Object next() {
                            Object v = iter.next();
                            if (type.isInstance(v)) {
                                matchCount.incrementAndGet();
                            }
                            return v;
                        }
                    }, type);
            Set<?> expected = (type == String.class) ? new HashSet<>(strings) : new HashSet<>(times);
            for (int c = 1; lazy.hasNext(); c++) {
                Object o = lazy.next();
                assertEquals("Mismatched match count for " + o, c, matchCount.get());
                assertTrue("Unexpected value: " + o, expected.remove(o));
            }
        }
    }
}
