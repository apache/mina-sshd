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

package org.apache.sshd.common.scp;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LocalFileScpTargetStreamResolver extends AbstractLoggingBean implements ScpTargetStreamResolver {
    private final Path path;
    private final Boolean status;
    private Path file;

    public LocalFileScpTargetStreamResolver(Path path) throws IOException {
        LinkOption[] options = IoUtils.getLinkOptions(false);
        this.status = IoUtils.checkFileExists(path, options);
        if (status == null) {
            throw new AccessDeniedException("Receive target file path existence status cannot be determined: " + path);
        }

        this.path = path;
    }

    @Override
    public OutputStream resolveTargetStream(String name, long length, Set<PosixFilePermission> perms) throws IOException {
        if (file != null) {
            throw new StreamCorruptedException("resolveTargetStream(" + name + ")[" + perms + "] already resolved: " + file);
        }

        LinkOption[] options = IoUtils.getLinkOptions(false);
        if (status && Files.isDirectory(path, options)) {
            String localName = name.replace('/', File.separatorChar);   // in case we are running on Windows
            file = path.resolve(localName);
        } else if (status && Files.isRegularFile(path, options)) {
            file = path;
        } else if (!status) {
            Path parent = path.getParent();

            Boolean parentStatus = IoUtils.checkFileExists(parent, options);
            if (parentStatus == null) {
                throw new AccessDeniedException("Receive file parent (" + parent + ") existence status cannot be determined for " + path);
            }

            if (parentStatus && Files.isDirectory(parent, options)) {
                file = path;
            }
        }

        if (file == null) {
            throw new IOException("Can not write to " + path);
        }

        Boolean fileStatus = IoUtils.checkFileExists(file, options);
        if (fileStatus == null) {
            throw new AccessDeniedException("Receive file existence status cannot be determined: " + file);
        }

        if (fileStatus) {
            if (Files.isDirectory(file, options)) {
                throw new IOException("File is a directory: " + file);
            }

            if (!Files.isWritable(file)) {
                throw new IOException("Can not write to file: " + file);
            }
        }

        if (log.isTraceEnabled()) {
            log.trace("resolveTargetStream(" + name + "): " + file);
        }

        return Files.newOutputStream(file);
    }

    @Override
    public Path getEventListenerFilePath() {
        if (file == null) {
            return path;
        } else {
            return file;
        }
    }

    @Override
    public void postProcessReceivedData(String name, boolean preserve, Set<PosixFilePermission> perms, ScpTimestamp time) throws IOException {
        if (file == null) {
            throw new StreamCorruptedException("postProcessReceivedData(" + name + ")[" + perms + "] No currently resolved data");
        }

        if (preserve) {
            updateFileProperties(name, file, perms, time);
        }
    }

    protected void updateFileProperties(String name, Path path, Set<PosixFilePermission> perms, ScpTimestamp time) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("updateFileProperties(" + name + ")[" + path + "] permissions: " + perms);
        }
        IoUtils.setPermissions(path, perms);

        if (time != null) {
            BasicFileAttributeView view = Files.getFileAttributeView(path, BasicFileAttributeView.class);
            FileTime lastModified = FileTime.from(time.getLastModifiedTime(), TimeUnit.MILLISECONDS);
            FileTime lastAccess = FileTime.from(time.getLastAccessTime(), TimeUnit.MILLISECONDS);
            if (log.isTraceEnabled()) {
                log.trace("updateFileProperties(" + name + ")[" + path + "] last-modified=" + lastModified + ", last-access=" + lastAccess);
            }

            view.setTimes(lastModified, lastAccess, null);
        }
    }

    @Override
    public String toString() {
        return String.valueOf(getEventListenerFilePath());
    }
}
