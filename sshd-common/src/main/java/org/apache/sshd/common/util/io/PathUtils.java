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

import java.nio.file.Path;
import java.util.Comparator;
import java.util.Objects;

import org.apache.sshd.common.util.GenericUtils;
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
        if (GenericUtils.isSameReference(p1, p2)) {
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
}
