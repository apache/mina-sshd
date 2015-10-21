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
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/**
 * @param <T> Type of information being extracted
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface FileInfoExtractor<T> {

    FileInfoExtractor<Boolean> EXISTS = new FileInfoExtractor<Boolean>() {
            @Override
            public Boolean infoOf(Path file, LinkOption... options) throws IOException {
                return Files.exists(file, options);
            }
        };

    FileInfoExtractor<Boolean> ISDIR = new FileInfoExtractor<Boolean>() {
            @Override
            public Boolean infoOf(Path file, LinkOption... options) throws IOException {
                return Files.isDirectory(file, options);
            }
        };

    FileInfoExtractor<Boolean> ISREG = new FileInfoExtractor<Boolean>() {
            @Override
            public Boolean infoOf(Path file, LinkOption... options) throws IOException {
                return Files.isRegularFile(file, options);
            }
        };

    FileInfoExtractor<Boolean> ISSYMLINK = new FileInfoExtractor<Boolean>() {
            @Override
            public Boolean infoOf(Path file, LinkOption... options) throws IOException {
                return Files.isSymbolicLink(file);
            }
        };

    FileInfoExtractor<Long> SIZE = new FileInfoExtractor<Long>() {
            @Override
            public Long infoOf(Path file, LinkOption... options) throws IOException {
                return Files.size(file);
            }
        };

    FileInfoExtractor<Set<PosixFilePermission>> PERMISSIONS = new FileInfoExtractor<Set<PosixFilePermission>>() {
            @Override
            public Set<PosixFilePermission> infoOf(Path file, LinkOption... options) throws IOException {
                return IoUtils.getPermissions(file, options);
            }
        };

    FileInfoExtractor<FileTime> LASTMODIFIED = new FileInfoExtractor<FileTime>() {
        @Override
        public FileTime infoOf(Path file, LinkOption... options) throws IOException {
            return Files.getLastModifiedTime(file, options);
        }

    };

    T infoOf(Path file, LinkOption ... options) throws IOException;

}
