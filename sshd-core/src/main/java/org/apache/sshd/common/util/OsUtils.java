/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.util;

/**
 * Operating system dependent utility methods.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class OsUtils {
    private static final boolean win32;

    static {
        String os = System.getProperty("os.name").toLowerCase();
        win32 = 0 <= os.indexOf("windows");
    }

    /** @return true if the host is a UNIX system (and not Windows). */
    public static boolean isUNIX() {
        return !win32;
    }

    /** @return true if the host is Windows (and not UNIX). */
    public static boolean isWin32() {
        return win32;
    }

    private OsUtils () {
    }
}
