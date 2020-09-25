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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.SelectorUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class PathScanningMatcher {
    /**
     * Whether or not the file system should be treated as a case sensitive one.
     */
    protected boolean caseSensitive = OsUtils.isUNIX();

    /**
     * The file separator to use to parse paths - default=local O/S separator
     */
    protected String separator = File.separator;

    /**
     * The patterns for the files to be included.
     */
    protected List<String> includePatterns;

    protected PathScanningMatcher() {
        super();
    }

    /**
     * <p>
     * Sets the list of include patterns to use. All '/' and '\' characters are replaced by
     * <code>File.separatorChar</code>, so the separator used need not match <code>File.separatorChar</code>.
     * </p>
     *
     * <p>
     * When a pattern ends with a '/' or '\', "**" is appended.
     * </p>
     *
     * @param includes A list of include patterns. May be {@code null}, indicating that all files should be included. If
     *                 a non-{@code null} list is given, all elements must be non-{@code null}.
     */
    public void setIncludes(String... includes) {
        setIncludes(GenericUtils.isEmpty(includes) ? Collections.emptyList() : Arrays.asList(includes));
    }

    /**
     * @return Un-modifiable list of the inclusion patterns
     */
    public List<String> getIncludes() {
        return includePatterns;
    }

    public void setIncludes(Collection<String> includes) {
        this.includePatterns = GenericUtils.isEmpty(includes)
                ? Collections.emptyList()
                : Collections.unmodifiableList(
                        includes.stream()
                                .map(v -> normalizePattern(v))
                                .collect(Collectors.toCollection(() -> new ArrayList<>(includes.size()))));
    }

    /**
     * @return Whether or not the file system should be treated as a case sensitive one.
     */
    public boolean isCaseSensitive() {
        return caseSensitive;
    }

    public void setCaseSensitive(boolean caseSensitive) {
        this.caseSensitive = caseSensitive;
    }

    /**
     * @return The file separator to use to parse paths - default=local O/S separator
     */
    public String getSeparator() {
        return separator;
    }

    public void setSeparator(String separator) {
        this.separator = ValidateUtils.checkNotNullAndNotEmpty(separator, "No separator provided");
    }

    /**
     * Tests whether or not a name matches against at least one include pattern.
     *
     * @param  name The name to match. Must not be {@code null}.
     * @return      <code>true</code> when the name matches against at least one include pattern, or <code>false</code>
     *              otherwise.
     */
    protected boolean isIncluded(String name) {
        Collection<String> includes = getIncludes();
        if (GenericUtils.isEmpty(includes)) {
            return false;
        }

        boolean cs = isCaseSensitive();
        String sep = getSeparator();
        for (String include : includes) {
            if (SelectorUtils.matchPath(include, name, sep, cs)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Tests whether or not a name matches the start of at least one include pattern.
     *
     * @param  name The name to match. Must not be {@code null}.
     * @return      <code>true</code> when the name matches against the start of at least one include pattern, or
     *              <code>false</code> otherwise.
     */
    protected boolean couldHoldIncluded(String name) {
        Collection<String> includes = getIncludes();
        if (GenericUtils.isEmpty(includes)) {
            return false;
        }

        boolean cs = isCaseSensitive();
        String sep = getSeparator();
        for (String include : includes) {
            if (SelectorUtils.matchPatternStart(include, name, sep, cs)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Normalizes the pattern, e.g. converts forward and backward slashes to the platform-specific file separator.
     *
     * @param  pattern The pattern to normalize, must not be {@code null}.
     * @return         The normalized pattern, never {@code null}.
     */
    public static String normalizePattern(String pattern) {
        pattern = pattern.trim();

        if (pattern.startsWith(SelectorUtils.REGEX_HANDLER_PREFIX)) {
            if (File.separatorChar == '\\') {
                pattern = GenericUtils.replace(pattern, "/", "\\\\", -1);
            } else {
                pattern = GenericUtils.replace(pattern, "\\\\", "/", -1);
            }
        } else {
            pattern = pattern.replace(File.separatorChar == '/' ? '\\' : '/', File.separatorChar);

            if (pattern.endsWith(File.separator)) {
                pattern += "**";
            }
        }

        return pattern;
    }
}
