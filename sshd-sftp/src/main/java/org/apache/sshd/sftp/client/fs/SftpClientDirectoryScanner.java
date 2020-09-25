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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.PathScanningMatcher;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.Attributes;
import org.apache.sshd.sftp.client.SftpClient.DirEntry;

/**
 * Uses an {@link SftpClient} to scan a directory (possibly recursively) and find files that match a given set of
 * inclusion patterns.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpClientDirectoryScanner extends PathScanningMatcher {
    protected String basedir;

    public SftpClientDirectoryScanner() {
        this(true);
    }

    public SftpClientDirectoryScanner(boolean caseSensitive) {
        setSeparator("/");
        setCaseSensitive(caseSensitive);
    }

    public SftpClientDirectoryScanner(String dir) {
        this(dir, Collections.emptyList());
    }

    public SftpClientDirectoryScanner(String dir, String... includes) {
        this(dir, GenericUtils.isEmpty(includes) ? Collections.emptyList() : Arrays.asList(includes));
    }

    public SftpClientDirectoryScanner(String dir, Collection<String> includes) {
        this();

        setBasedir(dir);
        setIncludes(includes);
    }

    public String getBasedir() {
        return basedir;
    }

    /**
     * @param basedir The base directory from which to start scanning. <B>Note:</B> it is converted to its canonical
     *                form when scanning. May not be {@code null}/empty
     */
    public void setBasedir(String basedir) {
        this.basedir = ValidateUtils.checkNotNullAndNotEmpty(basedir, "No base directory provided");
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
                                .map(v -> SftpPathDirectoryScanner.adjustPattern(v))
                                .collect(Collectors.toCollection(() -> new ArrayList<>(includes.size()))));
    }

    /**
     * Scans the current {@link #getBasedir() basedir}
     *
     * @param  client                The {@link SftpClient} instance to use
     * @return                       A {@link Collection} of {@link ScanDirEntry}-ies matching the {@link #getIncludes()
     *                               inclusion patterns}
     * @throws IOException           If failed to access the remote file system
     * @throws IllegalStateException If illegal/missing base directory, or missing inclusion patterns, or specified base
     *                               path is not a directory
     */
    public Collection<ScanDirEntry> scan(SftpClient client) throws IOException, IllegalStateException {
        return scan(client, LinkedList::new);
    }

    public <C extends Collection<ScanDirEntry>> C scan(
            SftpClient client, Supplier<? extends C> factory)
            throws IOException, IllegalStateException {
        String rootDir = getBasedir();
        ValidateUtils.checkState(GenericUtils.isNotEmpty(rootDir), "No basedir set");
        rootDir = client.canonicalPath(rootDir);

        Attributes attrs = client.stat(rootDir);
        if (attrs == null) {
            throw new IllegalStateException("basedir " + rootDir + " does not exist");
        }

        if (!attrs.isDirectory()) {
            throw new IllegalStateException("basedir " + rootDir + " is not a directory");
        }

        if (GenericUtils.isEmpty(getIncludes())) {
            throw new IllegalStateException("No includes set for " + rootDir);
        }

        return scandir(client, rootDir, "", factory.get());
    }

    /**
     * @param  <C>         Generic collection type
     * @param  client      The {@link SftpClient} instance to use
     * @param  rootDir     The <U>absolute</U> path of the folder to read
     * @param  parent      The <U>relative</U> parent of the folder to read - may be empty for base directory
     * @param  filesList   The (never {@code null}) {@link Collection} of {@link ScanDirEntry}-ies to update
     * @return             The updated {@link Collection} of {@link ScanDirEntry}-ies
     * @throws IOException If failed to access remote file system
     */
    protected <C extends Collection<ScanDirEntry>> C scandir(
            SftpClient client, String rootDir, String parent, C filesList)
            throws IOException {
        Collection<DirEntry> entries = client.readEntries(rootDir);
        if (GenericUtils.isEmpty(entries)) {
            return filesList;
        }

        for (DirEntry de : entries) {
            String name = de.getFilename();
            if (".".equals(name) || "..".equals(name)) {
                continue;
            }

            Attributes attrs = de.getAttributes();
            if (attrs.isDirectory()) {
                if (isIncluded(name)) {
                    String fullPath = createRelativePath(rootDir, name);
                    String relPath = createRelativePath(parent, name);
                    filesList.add(new ScanDirEntry(fullPath, relPath, de));
                    scandir(client, fullPath, relPath, filesList);
                } else if (couldHoldIncluded(name)) {
                    scandir(client, createRelativePath(rootDir, name), createRelativePath(parent, name), filesList);
                }
            } else if (attrs.isRegularFile()) {
                if (isIncluded(name)) {
                    filesList.add(new ScanDirEntry(createRelativePath(rootDir, name), createRelativePath(parent, name), de));
                }
            }
        }

        return filesList;
    }

    protected String createRelativePath(String parent, String name) {
        if (GenericUtils.isEmpty(parent)) {
            return name;
        } else {
            return parent + getSeparator() + name;
        }
    }

    /**
     * The result of a scan
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    public static class ScanDirEntry extends DirEntry {
        private final String fullPath;
        private final String relativePath;

        public ScanDirEntry(String fullPath, String relativePath, DirEntry dirEntry) {
            super(dirEntry);
            this.fullPath = fullPath;
            this.relativePath = relativePath;
        }

        /**
         * @return The full path represented by this entry
         */
        public String getFullPath() {
            return fullPath;
        }

        /**
         * @return The relative path from the base directory used for scanning
         */
        public String getRelativePath() {
            return relativePath;
        }

        @Override
        public String toString() {
            return getFullPath() + " - " + super.toString();
        }
    }
}
