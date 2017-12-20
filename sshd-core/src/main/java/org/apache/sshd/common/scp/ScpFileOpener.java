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
import java.io.InputStream;
import java.io.OutputStream;
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

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * Plug-in mechanism for users to intervene in the SCP process - e.g.,
 * apply some kind of traffic shaping mechanism, display upload/download
 * progress, etc...
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ScpFileOpener {
    /**
     * Invoked when receiving a new file to via a directory command
     *
     * @param localPath The target local path
     * @param name The target file name
     * @param boolean preserve Whether requested to preserve the permissions and timestamp
     * @param permissions The requested file permissions
     * @param time The requested {@link ScpTimestamp} - may be {@code null} if nothing to update
     * @return The actual target file path
     * @throws IOException If failed to resolve the file path
     * @see #updateFileProperties(Path, Set, ScpTimestamp) updateFileProperties
     */
    default Path resolveIncomingFilePath(
            Path localPath, String name, boolean preserve, Set<PosixFilePermission> permissions, ScpTimestamp time)
                    throws IOException {
        LinkOption[] options = IoUtils.getLinkOptions(true);
        Boolean status = IoUtils.checkFileExists(localPath, options);
        if (status == null) {
            throw new AccessDeniedException("Receive directory existence status cannot be determined: " + localPath);
        }

        Path file = null;
        if (status && Files.isDirectory(localPath, options)) {
            String localName = name.replace('/', File.separatorChar);
            file = localPath.resolve(localName);
        } else if (!status) {
            Path parent = localPath.getParent();

            status = IoUtils.checkFileExists(parent, options);
            if (status == null) {
                throw new AccessDeniedException("Receive directory parent (" + parent + ") existence status cannot be determined for " + localPath);
            }

            if (status && Files.isDirectory(parent, options)) {
                file = localPath;
            }
        }

        if (file == null) {
            throw new IOException("Cannot write to " + localPath);
        }

        status = IoUtils.checkFileExists(file, options);
        if (status == null) {
            throw new AccessDeniedException("Receive directory file existence status cannot be determined: " + file);
        }

        if (!(status && Files.isDirectory(file, options))) {
            Files.createDirectory(file);
        }

        if (preserve) {
            updateFileProperties(file, permissions, time);
        }

        return file;
    }

    /**
     * Invoked when a request to receive something is processed
     *
     * @param path The local target {@link Path} of the request
     * @param recursive Whether the request is recursive
     * @param shouldBeDir Whether target path is expected to be a directory
     * @param preserve Whether target path is expected to preserve attributes (permissions, times)
     * @return The effective target path - default=same as input
     * @throws IOException If failed to resolve target location
     */
    default Path resolveIncomingReceiveLocation(
            Path path, boolean recursive, boolean shouldBeDir, boolean preserve)
                throws IOException {
        if (!shouldBeDir) {
            return path;
        }
        LinkOption[] options = IoUtils.getLinkOptions(true);
        Boolean status = IoUtils.checkFileExists(path, options);
        if (status == null) {
            throw new SshException("Target directory " + path + " is most like inaccessible");
        }
        if (!status) {
            throw new SshException("Target directory " + path + " does not exist");
        }
        if (!Files.isDirectory(path, options)) {
            throw new SshException("Target directory " + path + " is not a directory");
        }

        return path;
    }

    /**
     * Called when there is a candidate file/folder for sending
     *
     * @param localPath The original file/folder {@link Path} for sending
     * @param options The {@link LinkOption}-s to use for validation
     * @return The effective outgoing file path (default=same as input)
     * @throws IOException If failed to resolve
     */
    default Path resolveOutgoingFilePath(Path localPath, LinkOption... options) throws IOException {
        Boolean status = IoUtils.checkFileExists(localPath, options);
        if (status == null) {
            throw new AccessDeniedException("Send file existence status cannot be determined: " + localPath);
        }
        if (!status) {
            throw new IOException(localPath + ": no such file or directory");
        }

        return localPath;
    }

    /**
     * Create an input stream to read from a file
     *
     * @param session The {@link Session} requesting the access
     * @param file The requested local file {@link Path}
     * @param options The {@link OpenOption}s - may be {@code null}/empty
     * @return The open {@link InputStream} never {@code null}
     * @throws IOException If failed to open the file
     */
    InputStream openRead(Session session, Path file, OpenOption... options) throws IOException;

    /**
     * Create an output stream to write to a file
     *
     * @param session The {@link Session} requesting the access
     * @param file The requested local file {@link Path}
     * @param options The {@link OpenOption}s - may be {@code null}/empty
     * @return The open {@link OutputStream} never {@code null}
     * @throws IOException If failed to open the file
     */
    OutputStream openWrite(Session session, Path file, OpenOption... options) throws IOException;

    static void updateFileProperties(Path file, Set<PosixFilePermission> perms, ScpTimestamp time) throws IOException {
        IoUtils.setPermissions(file, perms);

        if (time != null) {
            BasicFileAttributeView view = Files.getFileAttributeView(file, BasicFileAttributeView.class);
            FileTime lastModified = FileTime.from(time.getLastModifiedTime(), TimeUnit.MILLISECONDS);
            FileTime lastAccess = FileTime.from(time.getLastAccessTime(), TimeUnit.MILLISECONDS);
            view.setTimes(lastModified, lastAccess, null);
        }
    }
}
