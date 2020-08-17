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

package org.apache.sshd.scp.common.helpers;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.scp.common.ScpFileOpener;
import org.apache.sshd.scp.common.ScpTargetStreamResolver;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LocalFileScpTargetStreamResolver extends AbstractLoggingBean implements ScpTargetStreamResolver {
    protected final Path path;
    protected final ScpFileOpener opener;
    protected final Boolean status;
    private Path file;

    public LocalFileScpTargetStreamResolver(Path path, ScpFileOpener opener) throws IOException {
        LinkOption[] linkOptions = IoUtils.getLinkOptions(true);
        this.status = IoUtils.checkFileExists(path, linkOptions);
        if (status == null) {
            throw new AccessDeniedException("Receive target file path existence status cannot be determined: " + path);
        }

        this.path = path;
        this.opener = (opener == null) ? DefaultScpFileOpener.INSTANCE : opener;
    }

    @Override
    public OutputStream resolveTargetStream(
            Session session, String name, long length, Set<PosixFilePermission> perms, OpenOption... options)
            throws IOException {
        if (file != null) {
            throw new StreamCorruptedException("resolveTargetStream(" + name + ")[" + perms + "] already resolved: " + file);
        }

        LinkOption[] linkOptions = IoUtils.getLinkOptions(true);
        if (status && Files.isDirectory(path, linkOptions)) {
            String localName = name.replace('/', File.separatorChar); // in case we are running on Windows
            file = path.resolve(localName);
        } else if (status && Files.isRegularFile(path, linkOptions)) {
            file = path;
        } else if (!status) {
            Path parent = path.getParent();

            Boolean parentStatus = IoUtils.checkFileExists(parent, linkOptions);
            if (parentStatus == null) {
                throw new AccessDeniedException(
                        "Receive file parent (" + parent + ") existence status cannot be determined for " + path);
            }

            if (parentStatus && Files.isDirectory(parent, linkOptions)) {
                file = path;
            }
        }

        if (file == null) {
            throw new IOException("Can not write to " + path);
        }

        Boolean fileStatus = IoUtils.checkFileExists(file, linkOptions);
        if (fileStatus == null) {
            throw new AccessDeniedException("Receive file existence status cannot be determined: " + file);
        }

        if (fileStatus) {
            if (Files.isDirectory(file, linkOptions)) {
                throw new IOException("File is a directory: " + file);
            }

            if (!Files.isWritable(file)) {
                throw new IOException("Can not write to file: " + file);
            }
        }

        if (log.isTraceEnabled()) {
            log.trace("resolveTargetStream(" + name + "): " + file);
        }

        return opener.openWrite(session, file, length, perms, options);
    }

    @Override
    public void closeTargetStream(
            Session session, String name, long length, Set<PosixFilePermission> perms, OutputStream stream)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("closeTargetStream(" + name + "): " + file);
        }

        opener.closeWrite(session, file, length, perms, stream);
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
    public void postProcessReceivedData(
            String name, boolean preserve, Set<PosixFilePermission> perms, ScpTimestampCommandDetails time)
            throws IOException {
        if (file == null) {
            throw new StreamCorruptedException(
                    "postProcessReceivedData(" + name + ")[" + perms + "] No currently resolved data");
        }

        if (preserve) {
            updateFileProperties(name, file, perms, time);
        }
    }

    protected void updateFileProperties(
            String name, Path path, Set<PosixFilePermission> perms, ScpTimestampCommandDetails time)
            throws IOException {
        boolean traceEnabled = log.isTraceEnabled();
        if (traceEnabled) {
            log.trace("updateFileProperties(" + name + ")[" + path + "] permissions: " + perms);
        }
        IoUtils.setPermissions(path, perms);

        if (time != null) {
            BasicFileAttributeView view = Files.getFileAttributeView(path, BasicFileAttributeView.class);
            FileTime lastModified = FileTime.from(time.getLastModifiedTime(), TimeUnit.MILLISECONDS);
            FileTime lastAccess = FileTime.from(time.getLastAccessTime(), TimeUnit.MILLISECONDS);
            if (traceEnabled) {
                log.trace("updateFileProperties(" + name + ")[" + path + "] last-modified=" + lastModified + ", last-access="
                          + lastAccess);
            }

            view.setTimes(lastModified, lastAccess, null);
        }
    }

    @Override
    public String toString() {
        return String.valueOf(getEventListenerFilePath());
    }
}
