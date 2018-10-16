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

import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class VersionInfoTest extends JUnitTestSupport {
    public VersionInfoTest() {
        super();
    }

    @Test
    public void testLessThan4Components() {
        VersionInfo expected = new VersionInfo(73, 65);
        VersionInfo actual = VersionInfo.parse(NumberUtils.join('.', expected.getMajorVersion(), expected.getMinorVersion()));
        assertEquals("Mismatched result", expected, actual);
    }

    @Test
    public void testMoreThan4Components() {
        VersionInfo expected = new VersionInfo(7, 3, 6, 5);
        VersionInfo actual = VersionInfo.parse(expected.toString() + ".3.7.7.7.3.4.7");
        assertEquals("Mismatched result", expected, actual);
    }
}
