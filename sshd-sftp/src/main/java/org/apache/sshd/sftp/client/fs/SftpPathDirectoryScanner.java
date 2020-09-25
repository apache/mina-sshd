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

package org.apache.sshd.sftp.client.fs;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.SelectorUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.DirectoryScanner;

/**
 * An SFTP-aware {@link DirectoryScanner} that assumes all {@link Path}-s refer to SFTP remote ones and match patterns
 * use &quot;/&quot; as their separator with case sensitive matching by default (though the latter can be modified).
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpPathDirectoryScanner extends DirectoryScanner {
    public SftpPathDirectoryScanner() {
        this(true);
    }

    public SftpPathDirectoryScanner(boolean caseSensitive) {
        setSeparator("/");
        setCaseSensitive(caseSensitive);
    }

    public SftpPathDirectoryScanner(Path dir) {
        this(dir, Collections.emptyList());
    }

    public SftpPathDirectoryScanner(Path dir, String... includes) {
        this(dir, GenericUtils.isEmpty(includes) ? Collections.emptyList() : Arrays.asList(includes));
    }

    public SftpPathDirectoryScanner(Path dir, Collection<String> includes) {
        this();

        setBasedir(dir);
        setIncludes(includes);
    }

    @Override
    public String getSeparator() {
        return "/";
    }

    @Override
    public void setSeparator(String separator) {
        ValidateUtils.checkState("/".equals(separator), "Invalid separator: '%s'", separator);
        super.setSeparator(separator);
    }

    @Override
    public void setIncludes(Collection<String> includes) {
        this.includePatterns = GenericUtils.isEmpty(includes)
                ? Collections.emptyList()
                : Collections.unmodifiableList(
                        includes.stream()
                                .map(v -> adjustPattern(v))
                                .collect(Collectors.toCollection(() -> new ArrayList<>(includes.size()))));
    }

    public static String adjustPattern(String pattern) {
        pattern = pattern.trim();
        if ((!pattern.startsWith(SelectorUtils.REGEX_HANDLER_PREFIX)) && pattern.endsWith("/")) {
            return pattern + "**";
        }

        return pattern;
    }
}
