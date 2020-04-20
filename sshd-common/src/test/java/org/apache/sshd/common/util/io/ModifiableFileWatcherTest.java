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

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Assume;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class ModifiableFileWatcherTest extends JUnitTestSupport {
    public ModifiableFileWatcherTest() {
        super();
    }

    @Test // see SSHD-606
    public void testValidateStrictConfigFilePermissions() throws IOException {
        Assume.assumeTrue("Test does not always work on Windows", !OsUtils.isWin32());

        Path file = getTempTargetRelativeFile(getClass().getSimpleName(), getCurrentTestName());
        outputDebugMessage("%s deletion result=%s", file, Files.deleteIfExists(file));
        assertNull("Unexpected violation for non-existent file: " + file,
                ModifiableFileWatcher.validateStrictConfigFilePermissions(file));

        assertHierarchyTargetFolderExists(file.getParent());
        try (OutputStream output = Files.newOutputStream(file)) {
            output.write((getClass().getName() + "#" + getCurrentTestName() + "@" + new Date(System.currentTimeMillis()))
                    .getBytes(StandardCharsets.UTF_8));
        }

        Collection<PosixFilePermission> perms = IoUtils.getPermissions(file);
        if (GenericUtils.isEmpty(perms)) {
            assertNull("Unexpected violation for no permissions file: " + file,
                    ModifiableFileWatcher.validateStrictConfigFilePermissions(file));
        } else if (OsUtils.isUNIX()) {
            Map.Entry<String, Object> violation = null;
            for (PosixFilePermission p : ModifiableFileWatcher.STRICTLY_PROHIBITED_FILE_PERMISSION) {
                if (perms.contains(p)) {
                    violation = ModifiableFileWatcher.validateStrictConfigFilePermissions(file);
                    assertNotNull("Unexpected success for permission=" + p + " of file " + file + " permissions=" + perms,
                            violation);
                    break;
                }
            }

            if (violation == null) { // we do not expected a failure if no permissions have been violated
                assertNull("Unexpected UNIX violation for file " + file + " permissions=" + perms,
                        ModifiableFileWatcher.validateStrictConfigFilePermissions(file));
            }
        } else {
            assertNull("Unexpected Windows violation for file " + file + " permissions=" + perms,
                    ModifiableFileWatcher.validateStrictConfigFilePermissions(file));
        }
    }
}
