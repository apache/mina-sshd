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
     * Property that can be used to override the reported value from {@link #getCurrentUser()}. If not set then
     * &quot;user.name&quot; system property is used
     */
    public static final String CURRENT_USER_OVERRIDE_PROP = "org.apache.sshd.currentUser";

    /**
     * Property that can be used to override the reported value from {@link #getJavaVersion()}. If not set then
     * &quot;java.version&quot; system property is used
     */
    public static final String JAVA_VERSION_OVERRIDE_PROP = "org.apache.sshd.javaVersion";

    /**
     * Property that can be used to override the reported value from {@link #isWin32()}. If not set then
     * &quot;os.name&quot; system property is used
     */
    public static final String OS_TYPE_OVERRIDE_PROP = "org.apache.sshd.osType";

    public static final String WINDOWS_SHELL_COMMAND_NAME = "cmd.exe";
    public static final String LINUX_SHELL_COMMAND_NAME = "/bin/sh";

    public static final String ROOT_USER = "root";

    public static final List<String> LINUX_COMMAND
            = Collections.unmodifiableList(Arrays.asList(LINUX_SHELL_COMMAND_NAME, "-i", "-l"));
    public static final List<String> WINDOWS_COMMAND
            = Collections.unmodifiableList(Collections.singletonList(WINDOWS_SHELL_COMMAND_NAME));

    private static final AtomicReference<String> CURRENT_USER_HOLDER = new AtomicReference<>(null);
    private static final AtomicReference<VersionInfo> JAVA_VERSION_HOLDER = new AtomicReference<>(null);
    private static final AtomicReference<String> OS_TYPE_HOLDER = new AtomicReference<>(null);

    private OsUtils() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    /**
     * @return true if the host is a UNIX system (and not Windows).
     */
    public static boolean isUNIX() {
        return !isWin32() && !isOSX();
    }

    /**
     * @return true if the host is a OSX (and not Windows or Unix).
     */
    public static boolean isOSX() {
        return getOS().contains("mac");
    }

    /**
     * @return true if the host is Windows (and not UNIX).
     * @see    #OS_TYPE_OVERRIDE_PROP
     * @see    #setOS(String)
     */
    public static boolean isWin32() {
        return getOS().contains("windows");
    }

    /**
     * Can be used to enforce Win32 or Linux report from {@link #isWin32()}, {@link #isOSX()} or {@link #isUNIX()}
     *
     * @param os The value to set - if {@code null} then O/S type is auto-detected
     * @see      #isWin32()
     * @see      #isOSX()
     * @see      #isUNIX()
     */
    public static void setOS(String os) {
        synchronized (OS_TYPE_HOLDER) {
            OS_TYPE_HOLDER.set(os);
        }
    }

    /**
     * @return The resolved O/S type string if not already set (lowercase)
     */
    private static String getOS() {
        String typeValue;
        synchronized (OS_TYPE_HOLDER) {
            typeValue = OS_TYPE_HOLDER.get();
            if (typeValue != null) { // is it the 1st time
                return typeValue;
            }

            String value = System.getProperty(OS_TYPE_OVERRIDE_PROP, System.getProperty("os.name"));
            typeValue = GenericUtils.trimToEmpty(value).toLowerCase();
            OS_TYPE_HOLDER.set(typeValue);
        }

        return typeValue;
    }

    public static String resolveDefaultInteractiveShellCommand() {
        return resolveDefaultInteractiveShellCommand(isWin32());
    }

    public static String resolveDefaultInteractiveShellCommand(boolean winOS) {
        return winOS ? WINDOWS_SHELL_COMMAND_NAME : LINUX_SHELL_COMMAND_NAME + " -i -l";
    }

    public static List<String> resolveDefaultInteractiveCommandElements() {
        return resolveDefaultInteractiveCommandElements(isWin32());
    }

    public static List<String> resolveDefaultInteractiveCommandElements(boolean winOS) {
        if (winOS) {
            return WINDOWS_COMMAND;
        } else {
            return LINUX_COMMAND;
        }
    }

    /**
     * Get current user name
     *
     * @return Current user
     * @see    #CURRENT_USER_OVERRIDE_PROP
     */
    public static String getCurrentUser() {
        String username = null;
        synchronized (CURRENT_USER_HOLDER) {
            username = CURRENT_USER_HOLDER.get();
            if (username != null) { // have we already resolved it ?
                return username;
            }

            username = getCanonicalUser(System.getProperty(CURRENT_USER_OVERRIDE_PROP, System.getProperty("user.name")));
            ValidateUtils.checkNotNullAndNotEmpty(username, "No username available");
            CURRENT_USER_HOLDER.set(username);
        }

        return username;
    }

    /**
     * Remove {@code Windows} domain and/or group prefix as well as &quot;(User);&quot suffix
     *
     * @param  user The original username - ignored if {@code null}/empty
     * @return      The canonical user - unchanged if {@code Unix} O/S
     */
    public static String getCanonicalUser(String user) {
        if (GenericUtils.isEmpty(user)) {
            return user;
        }

        // Windows owner sometime has the domain and/or group prepended to it
        if (isWin32()) {
            int pos = user.lastIndexOf('\\');
            if (pos > 0) {
                user = user.substring(pos + 1);
            }

            pos = user.indexOf(' ');
            if (pos > 0) {
                user = user.substring(0, pos).trim();
            }
        }

        return user;
    }

    /**
     * Attempts to resolve canonical group name for {@code Windows}
     *
     * @param  group The original group name - used if not {@code null}/empty
     * @param  user  The owner name - sometimes it contains a group name
     * @return       The canonical group name
     */
    public static String resolveCanonicalGroup(String group, String user) {
        if (isUNIX()) {
            return group;
        }

        // we reach this code only for Windows
        if (GenericUtils.isEmpty(group)) {
            int pos = GenericUtils.isEmpty(user) ? -1 : user.lastIndexOf('\\');
            return (pos > 0) ? user.substring(0, pos) : group;
        }

        int pos = group.indexOf(' ');
        return (pos < 0) ? group : group.substring(0, pos).trim();
    }

    /**
     * Can be used to programmatically set the username reported by {@link #getCurrentUser()}
     *
     * @param username The username to set - if {@code null} then {@link #CURRENT_USER_OVERRIDE_PROP} will be consulted
     */
    public static void setCurrentUser(String username) {
        synchronized (CURRENT_USER_HOLDER) {
            CURRENT_USER_HOLDER.set(username);
        }
    }

    /**
     * Resolves the reported Java version by consulting {@link #JAVA_VERSION_OVERRIDE_PROP}. If not set, then
     * &quot;java.version&quot; property is used
     *
     * @return The resolved {@link VersionInfo} - never {@code null}
     * @see    #setJavaVersion(VersionInfo)
     */
    public static VersionInfo getJavaVersion() {
        VersionInfo version;
        synchronized (JAVA_VERSION_HOLDER) {
            version = JAVA_VERSION_HOLDER.get();
            if (version != null) { // first time ?
                return version;
            }

            String value = System.getProperty(JAVA_VERSION_OVERRIDE_PROP, System.getProperty("java.version"));
            // e.g.: 1.7.5_30
            value = ValidateUtils.checkNotNullAndNotEmpty(value, "No configured Java version value").replace('_', '.');
            // clean up any non-digits - in case something like 1.6.8_25-b323
            for (int index = 0; index < value.length(); index++) {
                char ch = value.charAt(index);
                if ((ch == '.') || ((ch >= '0') && (ch <= '9'))) {
                    continue;
                }

                value = value.substring(0, index);
                break;
            }

            version = ValidateUtils.checkNotNull(VersionInfo.parse(value), "No version parsed for %s", value);
            JAVA_VERSION_HOLDER.set(version);
        }

        return version;
    }

    /**
     * Set programmatically the reported Java version
     *
     * @param version The version - if {@code null} then it will be automatically resolved
     */
    public static void setJavaVersion(VersionInfo version) {
        synchronized (JAVA_VERSION_HOLDER) {
            JAVA_VERSION_HOLDER.set(version);
        }
    }

    /**
     * @param  path The original path
     * @return      A path that can be compared with another one where case sensitivity of the underlying O/S has been
     *              taken into account - never {@code null}
     */
    public static String getComparablePath(String path) {
        String p = (path == null) ? "" : path;
        return isWin32() ? p.toLowerCase() : p;
    }
}
