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

import java.util.Objects;

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
public class OsUtilsTest extends JUnitTestSupport {
    public OsUtilsTest() {
        super();
    }

    @Test
    public void testSetOsTypeByProperty() {
        try {
            for (String osType : new String[] { "Some-Windows", "Some-Linux" }) {
                OsUtils.setOS(null); // force re-detection

                try {
                    boolean expected = osType.contains("Windows");
                    System.setProperty(OsUtils.OS_TYPE_OVERRIDE_PROP, osType);
                    boolean actual = OsUtils.isWin32();
                    assertEquals(osType, expected, actual);
                } finally {
                    System.clearProperty(OsUtils.OS_TYPE_OVERRIDE_PROP);
                }
            }
        } finally {
            OsUtils.setOS(null); // force re-detection
        }
    }

    @Test
    public void testSetOsTypeProgrammatically() {
        try {
            OsUtils.setOS("windows 10");
            assertEquals("Mismatched detection value", false, OsUtils.isOSX());
            assertEquals("Mismatched detection value", false, OsUtils.isUNIX());
            assertEquals("Mismatched detection value", true, OsUtils.isWin32());

            OsUtils.setOS("mac os");
            assertEquals("Mismatched detection value", true, OsUtils.isOSX());
            assertEquals("Mismatched detection value", false, OsUtils.isUNIX());
            assertEquals("Mismatched detection value", false, OsUtils.isWin32());

            OsUtils.setOS("linux");
            assertEquals("Mismatched detection value", false, OsUtils.isOSX());
            assertEquals("Mismatched detection value", true, OsUtils.isUNIX());
            assertEquals("Mismatched detection value", false, OsUtils.isWin32());
        } finally {
            OsUtils.setOS(null); // force re-detection
        }
    }

    @Test
    public void testSetCurrentUserByProperty() {
        try {
            for (String expected : new String[] { getClass().getSimpleName(), getCurrentTestName() }) {
                OsUtils.setCurrentUser(null); // force re-detection

                try {
                    System.setProperty(OsUtils.CURRENT_USER_OVERRIDE_PROP, expected);
                    String actual = OsUtils.getCurrentUser();
                    assertEquals("Mismatched reported current user", expected, actual);
                } finally {
                    System.clearProperty(OsUtils.CURRENT_USER_OVERRIDE_PROP);
                }
            }
        } finally {
            OsUtils.setCurrentUser(null); // force re-detection
        }
    }

    @Test
    public void testSetCurrentUserProgrammatically() {
        try {
            for (String expected : new String[] { getClass().getSimpleName(), getCurrentTestName() }) {
                OsUtils.setCurrentUser(expected); // force value
                assertEquals("Mismatched detection value", expected, OsUtils.getCurrentUser());
            }
        } finally {
            OsUtils.setCurrentUser(null); // force re-detection
        }
    }

    @Test
    public void testSetJavaVersionByProperty() {
        try {
            for (String value : new String[] { "7.3.6_5", "37.77.34_7-" + getCurrentTestName() }) {
                OsUtils.setJavaVersion(null); // force re-detection

                try {
                    System.setProperty(OsUtils.JAVA_VERSION_OVERRIDE_PROP, value);
                    String expected = value.replace('_', '.');
                    String actual = Objects.toString(OsUtils.getJavaVersion(), null);
                    assertTrue("Mismatched reported version value: " + actual, expected.startsWith(actual));
                } finally {
                    System.clearProperty(OsUtils.JAVA_VERSION_OVERRIDE_PROP);
                }
            }
        } finally {
            OsUtils.setJavaVersion(null); // force re-detection
        }
    }

    @Test
    public void testSetJavaVersionProgrammatically() {
        try {
            for (VersionInfo expected : new VersionInfo[] { VersionInfo.parse("7.3.6.5"), VersionInfo.parse("37.77.34.7") }) {
                OsUtils.setJavaVersion(expected); // force value
                assertEquals("Mismatched detection value", expected, OsUtils.getJavaVersion());
            }
        } finally {
            OsUtils.setJavaVersion(null); // force re-detection
        }
    }
}
