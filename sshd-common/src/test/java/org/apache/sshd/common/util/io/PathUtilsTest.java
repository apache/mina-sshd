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
public class PathUtilsTest extends JUnitTestSupport {
    public PathUtilsTest() {
        super();
    }

    @Test
    void normalizeUserHomeOnlyPath() {
        Path expected = PathUtils.getUserHomeFolder();
        String actual = PathUtils.normalizePath(Character.toString(PathUtils.HOME_TILDE_CHAR));
        assertEquals(expected.toString(), actual);
    }

    @Test
    void normalizeLeadingUserHomePath() {
        Path expected = PathUtils.getUserHomeFolder()
                .resolve(getClass().getSimpleName())
                .resolve(getCurrentTestName());
        String actual = PathUtils.normalizePath(PathUtils.HOME_TILDE_CHAR
                                                + File.separator + getClass().getSimpleName()
                                                + File.separator + getCurrentTestName());
        assertEquals(expected.toString(), actual);
    }

    @Test
    void normalizeStandardPath() {
        String expected = detectTargetFolder().toString();
        String actual = PathUtils.normalizePath(expected);
        assertSame(expected, actual);
    }

    @Test
    void normalizeForwardSlash() {
        String expected = detectTargetFolder().toString();
        String actual = PathUtils.normalizePath(expected.replace(File.separatorChar, '/'));
        if (File.separatorChar == '/') {
            assertSame(expected, actual);
        } else {
            assertEquals(expected, actual);
        }
    }
}
