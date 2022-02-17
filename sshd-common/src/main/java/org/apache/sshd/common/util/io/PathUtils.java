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
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.Objects;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.functors.UnaryEquator;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class PathUtils {
    /** Compares 2 {@link Path}-s by their case insensitive {@link Path#getFileName() filename} */
    public static final Comparator<Path> BY_CASE_INSENSITIVE_FILENAME
            = (p1, p2) -> PathUtils.safeCompareFilename(p1, p2, false);

    public static final UnaryEquator<Path> EQ_CASE_INSENSITIVE_FILENAME
            = (p1, p2) -> BY_CASE_INSENSITIVE_FILENAME.compare(p1, p2) == 0;

    /** Compares 2 {@link Path}-s by their case sensitive {@link Path#getFileName() filename} */
    public static final Comparator<Path> BY_CASE_SENSITIVE_FILENAME = (p1, p2) -> PathUtils.safeCompareFilename(p1, p2, true);

    public static final UnaryEquator<Path> EQ_CASE_SENSITIVE_FILENAME
            = (p1, p2) -> BY_CASE_SENSITIVE_FILENAME.compare(p1, p2) == 0;

    private static final class LazyDefaultUserHomeFolderHolder {
        private static final Path PATH
                = Paths.get(ValidateUtils.checkNotNullAndNotEmpty(System.getProperty("user.home"), "No user home"))
                        .toAbsolutePath()
                        .normalize();

        private LazyDefaultUserHomeFolderHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    public static final char HOME_TILDE_CHAR = '~';

    /**
     * Private Constructor
     */
    private PathUtils() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    /**
     * Compares 2 {@link Path}-s by their {@link Path#getFileName() filename} while allowing for one or both to be
     * {@code null}.
     *
     * @param  p1            1st {@link Path}
     * @param  p2            2nd {@link Path}
     * @param  caseSensitive Whether comparison is case sensitive
     * @return               Comparison results - {@code null}-s are considered &quot;greater&quot; than
     *                       non-{@code null}-s
     */
    public static int safeCompareFilename(Path p1, Path p2, boolean caseSensitive) {
        if (UnaryEquator.isSameReference(p1, p2)) {
            return 0;
        } else if (p1 == null) {
            return 1;
        } else if (p2 == null) {
            return -1;
        }

        String n1 = Objects.toString(p1.getFileName(), null);
        String n2 = Objects.toString(p2.getFileName(), null);
        return GenericUtils.safeCompare(n1, n2, caseSensitive);
    }

    /**
     * <UL>
     * <LI>Replaces <U>leading</U> '~' with user's HOME directory</LI>
     * <LI>Replaces any forward slashes with the O/S directory separator</LI>
     * </UL>
     *
     * @param  path Input path - ignored if {@code null}/empty/blank
     * @return      Adjusted path
     */
    public static String normalizePath(String path) {
        if (GenericUtils.isBlank(path)) {
            return path;
        }

        if (path.charAt(0) == HOME_TILDE_CHAR) {
            Path homeDir = Objects.requireNonNull(getUserHomeFolder(), "No user home folder available");
            if (path.length() > 1) {
                path = homeDir + path.substring(1);
            } else {
                path = homeDir.toString();
            }
        }

        return path.replace('/', File.separatorChar);
    }

    /**
     * @return The {@link Path} to the currently running user home
     */
    @SuppressWarnings("synthetic-access")
    public static Path getUserHomeFolder() {
        return LazyDefaultUserHomeFolderHolder.PATH;
    }

    public static StringBuilder appendUserHome(StringBuilder sb) {
        return appendUserHome(sb, getUserHomeFolder());
    }

    public static StringBuilder appendUserHome(StringBuilder sb, Path userHome) {
        return appendUserHome(sb, Objects.requireNonNull(userHome, "No user home folder").toString());
    }

    public static StringBuilder appendUserHome(StringBuilder sb, String userHome) {
        if (GenericUtils.isEmpty(userHome)) {
            return sb;
        }

        sb.append(userHome);
        // strip any ending separator since we add our own
        int len = sb.length();
        if (sb.charAt(len - 1) == File.separatorChar) {
            sb.setLength(len - 1);
        }

        return sb;
    }
}
