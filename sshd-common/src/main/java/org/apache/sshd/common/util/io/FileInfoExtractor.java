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
 * @param  <T> Type of information being extracted
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface FileInfoExtractor<T> {

    FileInfoExtractor<Boolean> EXISTS = Files::exists;

    FileInfoExtractor<Boolean> ISDIR = Files::isDirectory;

    FileInfoExtractor<Boolean> ISREG = Files::isRegularFile;

    FileInfoExtractor<Boolean> ISSYMLINK = (file, options) -> Files.isSymbolicLink(file);

    FileInfoExtractor<Long> SIZE = (file, options) -> Files.size(file);

    FileInfoExtractor<Set<PosixFilePermission>> PERMISSIONS = IoUtils::getPermissions;

    FileInfoExtractor<FileTime> LASTMODIFIED = Files::getLastModifiedTime;

    T infoOf(Path file, LinkOption... options) throws IOException;

}
