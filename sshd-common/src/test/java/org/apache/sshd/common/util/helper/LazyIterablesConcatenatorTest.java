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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
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
public class LazyIterablesConcatenatorTest extends JUnitTestSupport {
    public LazyIterablesConcatenatorTest() {
        super();
    }

    @Test
    public void testLazyConcatenateIterables() {
        Collection<String> l1 = Arrays.asList(
                getCurrentTestName(),
                getClass().getSimpleName(),
                getClass().getPackage().getName());
        Collection<String> l2 = Arrays.asList(
                LocalDateTime.now().toString(),
                LocalTime.now().toString(),
                LocalDate.now().toString());
        List<String> expected = Stream.concat(l1.stream(), l2.stream()).collect(Collectors.toList());
        Iterable<String> iter = LazyIterablesConcatenator.lazyConcatenateIterables(Arrays.asList(l1, l2));
        List<String> actual = new ArrayList<>(expected.size());
        for (int index = 1, count = expected.size(); index <= count; index++) {
            actual.clear();

            for (String s : iter) {
                actual.add(s);
            }

            assertListEquals("Attempt #" + index, expected, actual);
        }
    }
}
