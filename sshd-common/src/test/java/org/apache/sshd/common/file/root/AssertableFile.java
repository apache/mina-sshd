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

package org.apache.sshd.common.file.root;

import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.util.test.JUnitTestSupport;

/**
 * TODO upgrade to default methods in JDK 8
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AssertableFile extends JUnitTestSupport {
    protected AssertableFile() {
        super();
    }

    public static boolean notExists(Path p) {
        boolean cond = !Files.exists(p);
        assertTrue(p + " does not exist", cond);
        return cond;
    }

    public static boolean exists(Path p) {
        boolean cond = Files.exists(p);
        assertTrue(p + " exists", cond);
        return cond;
    }

    public static boolean isDir(Path p) {
        boolean cond = Files.isDirectory(p);
        assertTrue(p + " is directory", cond);
        return cond;
    }

    public static boolean isReadable(Path p) {
        boolean cond = Files.isReadable(p);
        assertTrue(p + " is readable by user", cond);
        return cond;
    }

    public static boolean isNonEmpty(byte[] bytes) {
        boolean cond = !NumberUtils.isEmpty(bytes);
        assertTrue("bytes are non empty", cond);
        return cond;
    }

    public static boolean isRootedAt(Path root, Path check) {
        boolean cond = check.toAbsolutePath().normalize().startsWith(root.toAbsolutePath().normalize());
        assertTrue(check + " is subpath of parent " + root, cond);
        return cond;
    }
}
