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

import java.io.InputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Random;
import java.util.TreeSet;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class DHGroupDataParseTest extends BaseTestSupport {
    private final String name;
    private final byte[] expected;

    public DHGroupDataParseTest(String name, byte[] expected) {
        this.name = name;
        this.expected = expected;
    }

    @Parameters(name = "{0}") // Note: we rely on the naming convention
    public static List<Object[]> parameters() throws Exception {
        Collection<String> processedResources = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        List<Object[]> testCases = new ArrayList<>();
        for (Method m : DHGroupData.class.getMethods()) {
            int mods = m.getModifiers();
            if ((!Modifier.isPublic(mods)) || (!Modifier.isStatic(mods))) {
                continue;
            }

            String name = m.getName();
            if (!name.startsWith("getP")) {
                continue;
            }

            int groupId = -1;
            for (int pos = name.length() - 1; pos >= 0; pos--) {
                char ch = name.charAt(pos);
                if (Character.isDigit(ch)) {
                    continue;
                }

                String value = name.substring(pos + 1);
                groupId = Integer.parseInt(value);
                break;
            }

            assertTrue("Cannot extract group ID from " + name, groupId > 0);

            // For some reason, P1 is stored in 'group2.prime' - TODO standardize the naming convention
            if (groupId == 1) {
                groupId = 2;
            }
            String resName = "group" + groupId + ".prime";
            assertTrue("Duplicate resource name: " + resName, processedResources.add(resName));

            byte[] expected = (byte[]) m.invoke(null, GenericUtils.EMPTY_OBJECT_ARRAY);
            testCases.add(new Object[] { resName, expected });
        }

        assertFalse("No resources processed", processedResources.isEmpty());
        return testCases;
    }

    @Test
    public void testParseOakleyGroupPrimeValues() throws Exception {
        List<String> lines;
        try (InputStream stream = DHGroupData.class.getResourceAsStream(name)) {
            assertNotNull("Missing prime value file for group=" + name, stream);
            lines = IoUtils.readAllLines(stream);
        }

        List<String> dataLines = new ArrayList<>();
        List<String> otherLines = new ArrayList<>();
        for (String raw : lines) {
            String l = GenericUtils.trimToEmpty(raw);
            l = l.replaceAll("\\s", "");
            if (GenericUtils.isEmpty(l) || l.startsWith("#")) {
                otherLines.add(raw);
            } else {
                dataLines.add(raw);
            }
        }

        Random rnd = new Random(System.nanoTime());
        for (int index = 1, numDataLines = dataLines.size(), numOtherLines = otherLines.size(); index <= 4; index++) {
            byte[] actual = DHGroupData.readOakleyGroupPrimeValue(lines.stream());
            assertArrayEquals(name + "[" + index + "]", expected, actual);
            lines.clear();

            // create an interleaving of the data lines and the other ones
            for (int dataIndex = 0, otherIndex = 0; (dataIndex < numDataLines) || (otherIndex < numOtherLines);) {
                String l;
                if (dataIndex < numDataLines) {
                    if (otherIndex < numOtherLines) {
                        if (rnd.nextBoolean()) {
                            l = dataLines.get(dataIndex);
                            dataIndex++;
                        } else {
                            l = otherLines.get(otherIndex);
                            otherIndex++;
                        }
                    } else {
                        l = dataLines.get(dataIndex);
                        dataIndex++;
                    }
                } else if (otherIndex < numOtherLines) {
                    l = otherLines.get(otherIndex);
                    otherIndex++;
                } else {
                    throw new IllegalStateException("No more lines to interleave");
                }

                lines.add(l);
            }
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + name + "]";
    }
}
