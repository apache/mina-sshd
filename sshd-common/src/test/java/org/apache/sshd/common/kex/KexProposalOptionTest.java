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

package org.apache.sshd.common.kex;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Collection;
import java.util.EnumSet;

import org.apache.sshd.common.kex.KexProposalOption.Constants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class KexProposalOptionTest extends JUnitTestSupport {
    public KexProposalOptionTest() {
        super();
    }

    @Test
    void fromUnmatchedName() {
        for (String n : new String[] { null, "", getCurrentTestName() }) {
            KexProposalOption o = KexProposalOption.fromName(n);
            assertNull(o, "Unexpected value for name='" + n + "'");
        }
    }

    @Test
    void fromMatchedName() {
        for (KexProposalOption expected : KexProposalOption.VALUES) {
            String n = expected.name();

            for (int index = 0; index < n.length(); index++) {
                KexProposalOption actual = KexProposalOption.fromName(n);
                assertSame(expected, actual, "Mismatched option for name=" + n);
                n = shuffleCase(n); // prepare for next iteration
            }
        }
    }

    @Test
    void fromUnmatchedProposalIndex() {
        for (int index : new int[] { -1, KexProposalOption.VALUES.size() }) {
            KexProposalOption o = KexProposalOption.fromProposalIndex(index);
            assertNull(o, "Unexpected value for index=" + index);
        }
    }

    @Test
    void fromMatchedProposalIndex() {
        for (KexProposalOption expected : KexProposalOption.VALUES) {
            int index = expected.getProposalIndex();
            KexProposalOption actual = KexProposalOption.fromProposalIndex(index);
            assertSame(expected, actual, "Mismatched values for index=" + index);
        }
    }

    @Test
    void byProposalIndexSortOrder() {
        for (int index = 0; index < KexProposalOption.VALUES.size(); index++) {
            if (index < 1) {
                continue;
            }

            KexProposalOption o1 = KexProposalOption.VALUES.get(index - 1);
            KexProposalOption o2 = KexProposalOption.VALUES.get(index);

            int i1 = o1.getProposalIndex();
            int i2 = o2.getProposalIndex();
            assertTrue(i1 < i2, "Non increasing index for " + o1 + "[" + i1 + "] vs. " + o2 + "[" + i2 + "]");
        }
    }

    @Test
    void allConstantsCovered() throws Exception {
        Field[] fields = Constants.class.getFields();

        Collection<KexProposalOption> options = EnumSet.allOf(KexProposalOption.class);
        for (Field f : fields) {
            int mods = f.getModifiers();
            if (!Modifier.isStatic(mods)) {
                continue;
            }

            Class<?> type = f.getType();
            if (!Integer.TYPE.isAssignableFrom(type)) {
                continue;
            }

            int index = f.getInt(null);
            KexProposalOption o = KexProposalOption.fromProposalIndex(index);
            assertNotNull(o, "No matching option for index=" + index);
            assertTrue(options.remove(o), "Option not in known options: " + o);
        }

        assertTrue(GenericUtils.isEmpty(options), "Not all options covered: " + options);
    }
}
