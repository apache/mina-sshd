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
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class OsUtilsTest extends JUnitTestSupport {
    public OsUtilsTest() {
        super();
    }

    @Test
    void setOsTypeByProperty() {
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
    void setOsTypeProgrammatically() {
        try {
            OsUtils.setOS("windows 10");
            assertEquals("Mismatched detection value", false, OsUtils.isOSX());
            assertEquals("Mismatched detection value", false, OsUtils.isUNIX());
            assertEquals("Mismatched detection value", true, OsUtils.isWin32());
            assertEquals("Mismatched detection value", false, OsUtils.isAndroid());

            OsUtils.setOS("mac os");
            assertEquals("Mismatched detection value", true, OsUtils.isOSX());
            assertEquals("Mismatched detection value", false, OsUtils.isUNIX());
            assertEquals("Mismatched detection value", false, OsUtils.isWin32());
            assertEquals("Mismatched detection value", false, OsUtils.isAndroid());

            OsUtils.setOS("linux");
            assertEquals("Mismatched detection value", false, OsUtils.isOSX());
            assertEquals("Mismatched detection value", true, OsUtils.isUNIX());
            assertEquals("Mismatched detection value", false, OsUtils.isWin32());
            assertEquals("Mismatched detection value", false, OsUtils.isAndroid());
        } finally {
            OsUtils.setOS(null); // force re-detection
        }
    }

    @Test
    void setCurrentUserByProperty() {
        try {
            for (String expected : new String[] { getClass().getSimpleName(), getCurrentTestName() }) {
                OsUtils.setCurrentUser(null); // force re-detection

                try {
                    System.setProperty(OsUtils.CURRENT_USER_OVERRIDE_PROP, expected);
                    String actual = OsUtils.getCurrentUser();
                    assertEquals(expected, actual, "Mismatched reported current user");
                } finally {
                    System.clearProperty(OsUtils.CURRENT_USER_OVERRIDE_PROP);
                }
            }
        } finally {
            OsUtils.setCurrentUser(null); // force re-detection
        }
    }

    @Test
    void setCurrentUserProgrammatically() {
        try {
            for (String expected : new String[] { getClass().getSimpleName(), getCurrentTestName() }) {
                OsUtils.setCurrentUser(expected); // force value
                assertEquals(expected, OsUtils.getCurrentUser(), "Mismatched detection value");
            }
        } finally {
            OsUtils.setCurrentUser(null); // force re-detection
        }
    }

    @Test
    void setJavaVersionByProperty() {
        try {
            for (String value : new String[] { "7.3.6_5", "37.77.34_7-" + getCurrentTestName() }) {
                OsUtils.setJavaVersion(null); // force re-detection

                try {
                    System.setProperty(OsUtils.JAVA_VERSION_OVERRIDE_PROP, value);
                    String expected = value.replace('_', '.');
                    String actual = Objects.toString(OsUtils.getJavaVersion(), null);
                    assertTrue(expected.startsWith(actual), "Mismatched reported version value: " + actual);
                } finally {
                    System.clearProperty(OsUtils.JAVA_VERSION_OVERRIDE_PROP);
                }
            }
        } finally {
            OsUtils.setJavaVersion(null); // force re-detection
        }
    }

    @Test
    void setJavaVersionProgrammatically() {
        try {
            for (VersionInfo expected : new VersionInfo[] { VersionInfo.parse("7.3.6.5"), VersionInfo.parse("37.77.34.7") }) {
                OsUtils.setJavaVersion(expected); // force value
                assertEquals(expected, OsUtils.getJavaVersion(), "Mismatched detection value");
            }
        } finally {
            OsUtils.setJavaVersion(null); // force re-detection
        }
    }
}
