/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.common.util;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.util.BaseTestSupport;
import org.junit.Test;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class GenericUtilsTest extends BaseTestSupport {
    public GenericUtilsTest() {
        super();
    }

    @Test
    public void testSplitAndJoin() {
        List<String>  expected=Collections.unmodifiableList(
                Arrays.asList(getClass().getPackage().getName().replace('.', '/'), getClass().getSimpleName(), getCurrentTestName()));

        // NOTE: we also test characters that have meaning in String.split(...) as regex ones
        for (char ch : new char[] { ',', '.', '*', '?' }) {
            String      sep=String.valueOf(ch);
            String      s=GenericUtils.join(expected, sep);
            String[]    actual=GenericUtils.split(s, ch);
            assertEquals("Mismatched split length for separator=" + sep, expected.size(), GenericUtils.length((Object[]) actual));
            
            for (int index=0; index < actual.length; index++) {
                String  e=expected.get(index), a=actual[index];
                if (!e.endsWith(a)) {
                    fail("Mismatched value at index=" + index + " for separator=" + sep + ": expected=" + e + ", actual=" + a);
                }
            }
        }
    }
}
