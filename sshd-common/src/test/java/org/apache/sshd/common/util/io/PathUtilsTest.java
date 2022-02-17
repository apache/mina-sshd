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

package org.apache.sshd.common.util.io;

import java.io.File;
import java.nio.file.Path;

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
public class PathUtilsTest extends JUnitTestSupport {
    public PathUtilsTest() {
        super();
    }

    @Test
    public void testNormalizeUserHomeOnlyPath() {
        Path expected = PathUtils.getUserHomeFolder();
        String actual = PathUtils.normalizePath(Character.toString(PathUtils.HOME_TILDE_CHAR));
        assertEquals(expected.toString(), actual);
    }

    @Test
    public void testNormalizeLeadingUserHomePath() {
        Path expected = PathUtils.getUserHomeFolder()
                .resolve(getClass().getSimpleName())
                .resolve(getCurrentTestName())
                ;
        String actual = PathUtils.normalizePath(PathUtils.HOME_TILDE_CHAR
            + File.separator + getClass().getSimpleName()
            + File.separator + getCurrentTestName());
        assertEquals(expected.toString(), actual);
    }

    @Test
    public void testNormalizeStandardPath() {
        String expected = detectTargetFolder().toString();
        String actual = PathUtils.normalizePath(expected);
        assertSame(expected, actual);
    }

    @Test
    public void testNormalizeForwardSlash() {
        String expected = detectTargetFolder().toString();
        String actual = PathUtils.normalizePath(expected.replace(File.separatorChar, '/'));
        if (File.separatorChar == '/') {
            assertSame(expected, actual);
        } else {
            assertEquals(expected, actual);
        }
    }
}
