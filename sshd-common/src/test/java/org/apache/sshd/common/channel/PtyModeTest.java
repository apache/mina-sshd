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

package org.apache.sshd.common.channel;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

import org.apache.sshd.common.util.GenericUtils;
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
public class PtyModeTest extends JUnitTestSupport {
    public PtyModeTest() {
        super();
    }

    @Test
    public void testOpcodeExtractorOnNull() {
        assertEquals(-1, PtyMode.OPCODE_EXTRACTOR.applyAsInt(null));
    }

    @Test
    public void testEnabledOptions() {
        Set<PtyMode> expected = EnumSet.of(PtyMode.ECHO, PtyMode.CS8, PtyMode.ICANON);
        Map<PtyMode, Integer> modes = PtyMode.createEnabledOptions(expected);
        assertEquals("Mismatched modes size", expected.size(), GenericUtils.size(modes));

        for (PtyMode m : expected) {
            assertSame("Mismatched setting for " + m, PtyMode.TRUE_SETTING, modes.get(m));
        }

        Set<PtyMode> actual = PtyMode.resolveEnabledOptions(modes, expected);
        assertEquals("Mismatched enabled options", expected, actual);
    }
}
