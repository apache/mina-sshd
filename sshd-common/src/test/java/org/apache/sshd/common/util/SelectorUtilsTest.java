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

import java.io.File;
import java.util.Random;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class SelectorUtilsTest extends JUnitTestSupport {
    public SelectorUtilsTest() {
        super();
    }

    @Test
    void applyLinuxSeparatorSlashifyRules() {
        testApplySlashifyRules('/');
    }

    @Test
    void applyWindowsSeparatorSlashifyRules() {
        testApplySlashifyRules('\\');
    }

    private void testApplySlashifyRules(char slash) {
        for (String expected : new String[] {
                null, "", getCurrentTestName(),
                getClass().getSimpleName() + Character.toString(slash) + getCurrentTestName(),
                Character.toString(slash) + getClass().getSimpleName(),
                Character.toString(slash) + getClass().getSimpleName() + Character.toString(slash) + getCurrentTestName()
        }) {
            String actual = SelectorUtils.applySlashifyRules(expected, slash);
            assertSame(expected, actual, "Mismatched results for '" + expected + "'");
        }

        String[] comps = { getClass().getSimpleName(), getCurrentTestName() };
        Random rnd = new Random(System.nanoTime());
        StringBuilder sb = new StringBuilder(Byte.MAX_VALUE);
        for (int index = 0; index < Long.SIZE; index++) {
            if (sb.length() > 0) {
                sb.setLength(0); // start from scratch
            }

            boolean prepend = rnd.nextBoolean();
            if (prepend) {
                slashify(sb, rnd, slash);
            }

            sb.append(comps[0]);
            for (int j = 1; j < comps.length; j++) {
                slashify(sb, rnd, slash);
                sb.append(comps[j]);
            }

            boolean append = rnd.nextBoolean();
            if (append) {
                slashify(sb, rnd, slash);
            }

            String path = sb.toString();
            sb.setLength(0);
            if (prepend) {
                sb.append(slash);
            }

            sb.append(comps[0]);
            for (int j = 1; j < comps.length; j++) {
                sb.append(slash).append(comps[j]);
            }

            if (append) {
                sb.append(slash).append('.');
            }

            String expected = sb.toString();
            String actual = SelectorUtils.applySlashifyRules(path, slash);
            assertEquals(expected, actual, "Mismatched results for path=" + path);
        }
    }

    private static int slashify(StringBuilder sb, Random rnd, char slash) {
        int slashes = 1 /* at least one slash */ + rnd.nextInt(Byte.SIZE);
        for (int k = 0; k < slashes; k++) {
            sb.append(slash);
        }

        return slashes;
    }

    @Test
    void translateToFileSystemPath() {
        String path = getClass().getPackage().getName().replace('.', File.separatorChar)
                      + File.separator + getClass().getSimpleName()
                      + File.separator + getCurrentTestName();
        for (String expected : new String[] { null, "", path }) {
            String actual = SelectorUtils.translateToFileSystemPath(expected, File.separator, File.separator);
            assertSame(expected, actual, "Mismatched instance for translated result");
        }

        for (String fsSeparator : new String[] { String.valueOf('.'), "##" }) {
            String expected = path.replace(File.separator, fsSeparator);
            String actual = SelectorUtils.translateToFileSystemPath(path, File.separator, fsSeparator);
            assertEquals(expected, actual, "Mismatched translation result for separator='" + fsSeparator + "'");

            actual = SelectorUtils.translateToFileSystemPath(actual, fsSeparator, File.separator);
            assertEquals(path, actual, "Mismatched translation revert for separator='" + fsSeparator + "'");
        }
    }

    @Test
    void absoluteWindowsPathTranslation() {
        Assumptions.assumeTrue(OsUtils.isWin32(), "Windows-specific test skipped");
        String expected = detectTargetFolder().toString();
        for (String prefix : new String[] { "", "/" }) {
            String actual = SelectorUtils.translateToLocalPath(prefix + expected.replace('/', File.separatorChar));
            assertEquals(expected, actual, "Mismatched result for prefix='" + prefix + "'");
        }
    }

    @Test
    void concatPathsOneEmptyOrNull() {
        String path = getCurrentTestName();
        assertSame(path, SelectorUtils.concatPaths(null, path, File.separatorChar), "Null 1st");
        assertSame(path, SelectorUtils.concatPaths("", path, File.separatorChar), "Empty 1st");
        assertSame(path, SelectorUtils.concatPaths(path, null, File.separatorChar), "Null 2nd");
        assertSame(path, SelectorUtils.concatPaths(path, "", File.separatorChar), "Empty 2nd");
    }
}
