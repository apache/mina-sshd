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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Operating system dependent utility methods.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class OsUtils {

    /**
     * Property that can be used to override the reported value from {@link #getCurrentUser()}.
     * If not set then &quot;user.name&quot; system property is used
     */
    public static final String CURRENT_USER_OVERRIDE_PROP = "org.apache.sshd.currentUser";

    public static final String WINDOWS_SHELL_COMMAND_NAME = "cmd.exe";
    public static final String LINUX_SHELL_COMMAND_NAME = "/bin/sh";

    public static final String ROOT_USER = "root";

    public static final List<String> LINUX_COMMAND =
            Collections.unmodifiableList(Arrays.asList(LINUX_SHELL_COMMAND_NAME, "-i", "-l"));
    public static final List<String> WINDOWS_COMMAND =
            Collections.unmodifiableList(Collections.singletonList(WINDOWS_SHELL_COMMAND_NAME));

    private static final AtomicReference<String> CURRENT_USER_HOLDER = new AtomicReference<>(null);
    private static final boolean WIN32 = GenericUtils.trimToEmpty(System.getProperty("os.name")).toLowerCase().contains("windows");

    private OsUtils() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    /**
     * @return true if the host is a UNIX system (and not Windows).
     */
    public static boolean isUNIX() {
        return !WIN32;
    }

    /**
     * @return true if the host is Windows (and not UNIX).
     */
    public static boolean isWin32() {
        return WIN32;
    }

    public static List<String> resolveDefaultInteractiveCommand() {
        return resolveInteractiveCommand(isWin32());
    }

    public static List<String> resolveInteractiveCommand(boolean isWin32) {
        if (isWin32) {
            return WINDOWS_COMMAND;
        } else {
            return LINUX_COMMAND;
        }
    }

    /**
     * Get current user name
     *
     * @return Current user
     * @see #CURRENT_USER_OVERRIDE_PROP
     */
    public static String getCurrentUser() {
        String username = null;
        synchronized (CURRENT_USER_HOLDER) {
            username = CURRENT_USER_HOLDER.get();
            if (username != null) {  // have we already resolved it ?
                return username;
            }

            username = System.getProperty(CURRENT_USER_OVERRIDE_PROP, System.getProperty("user.name"));
            ValidateUtils.checkNotNullAndNotEmpty(username, "No username available");
            CURRENT_USER_HOLDER.set(username);
        }

        return username;
    }

    /**
     * Can be used to programmatically set the username reported by {@link #getCurrentUser()}
     * @param username The username to set - if {@code null} then {@link #CURRENT_USER_OVERRIDE_PROP}
     * will be consulted
     */
    public static void setCurrentUser(String username) {
        synchronized (CURRENT_USER_HOLDER) {
            CURRENT_USER_HOLDER.set(username);
        }
    }
}
