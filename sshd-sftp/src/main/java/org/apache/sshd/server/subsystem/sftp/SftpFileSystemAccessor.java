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

package org.apache.sshd.server.subsystem.sftp;

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.nio.channels.Channel;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.util.Collections;
import java.util.List;
import java.util.NavigableMap;
import java.util.Set;

import org.apache.sshd.common.util.MapEntryUtils.NavigableMapBuilder;
import org.apache.sshd.common.util.io.FileInfoExtractor;
import org.apache.sshd.server.session.ServerSession;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SftpFileSystemAccessor {
    List<String> DEFAULT_UNIX_VIEW = Collections.singletonList("unix:*");

    /**
     * A case <U>insensitive</U> {@link NavigableMap} of {@link FileInfoExtractor}s to
     * be used to complete attributes that are deemed important enough to warrant an
     * extra effort if not accessible via the file system attributes views
     */
    NavigableMap<String, FileInfoExtractor<?>> FILEATTRS_RESOLVERS =
        NavigableMapBuilder.<String, FileInfoExtractor<?>>builder(String.CASE_INSENSITIVE_ORDER)
            .put("isRegularFile", FileInfoExtractor.ISREG)
            .put("isDirectory", FileInfoExtractor.ISDIR)
            .put("isSymbolicLink", FileInfoExtractor.ISSYMLINK)
            .put("permissions", FileInfoExtractor.PERMISSIONS)
            .put("size", FileInfoExtractor.SIZE)
            .put("lastModifiedTime", FileInfoExtractor.LASTMODIFIED)
            .immutable();

    SftpFileSystemAccessor DEFAULT = new SftpFileSystemAccessor() {
        @Override
        public String toString() {
            return SftpFileSystemAccessor.class.getSimpleName() + "[DEFAULT]";
        }
    };

    /**
     * Called whenever a new file is opened
     *
     * @param session The {@link ServerSession} through which the request was received
     * @param subsystem The SFTP subsystem instance that manages the session
     * @param file The requested <U>local</U> file {@link Path}
     * @param handle The assigned file handle through which the remote peer references this file.
     * May be {@code null}/empty if the request is due to some internal functionality
     * instead of due to peer requesting a handle to a file.
     * @param options The requested {@link OpenOption}s
     * @param attrs The requested {@link FileAttribute}s
     * @return The opened {@link SeekableByteChannel}
     * @throws IOException If failed to open
     */
    default SeekableByteChannel openFile(
            ServerSession session, SftpEventListenerManager subsystem,
            Path file, String handle, Set<? extends OpenOption> options, FileAttribute<?>... attrs)
                throws IOException {
        return FileChannel.open(file, options, attrs);
    }

    /**
     * Called when locking a section of a file is requested
     *
     * @param session The {@link ServerSession} through which the request was received
     * @param subsystem The SFTP subsystem instance that manages the session
     * @param file The requested <U>local</U> file {@link Path}
     * @param handle The assigned file handle through which the remote peer references this file
     * @param channel The original {@link Channel} that was returned by {@link #openFile(ServerSession, SftpEventListenerManager, Path, String, Set, FileAttribute...)}
     * @param position The position at which the locked region is to start - must be non-negative
     * @param size The size of the locked region; must be non-negative, and the sum
     * <tt>position</tt>&nbsp;+&nbsp;<tt>size</tt> must be non-negative
     * @param shared {@code true} to request a shared lock, {@code false} to request an exclusive lock
     * @return A lock object representing the newly-acquired lock, or {@code null}
     * if the lock could not be acquired because another program holds an overlapping lock
     * @throws IOException If failed to honor the request
     * @see FileChannel#tryLock(long, long, boolean)
     */
    default FileLock tryLock(ServerSession session, SftpEventListenerManager subsystem,
            Path file, String handle, Channel channel, long position, long size, boolean shared)
                throws IOException {
        if (!(channel instanceof FileChannel)) {
            throw new StreamCorruptedException("Non file channel to lock: " + channel);
        }

        return ((FileChannel) channel).lock(position, size, shared);
    }

    /**
     * Called when file meta-data re-synchronization is required
     *
     * @param session The {@link ServerSession} through which the request was received
     * @param subsystem The SFTP subsystem instance that manages the session
     * @param file The requested <U>local</U> file {@link Path}
     * @param handle The assigned file handle through which the remote peer references this file
     * @param channel The original {@link Channel} that was returned by {@link #openFile(ServerSession, SftpEventListenerManager, Path, String, Set, FileAttribute...)}
     * @throws IOException If failed to execute the request
     * @see FileChannel#force(boolean)
     * @see <A HREF="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL">OpenSSH -  section 10</A>
     */
    default void syncFileData(
            ServerSession session, SftpEventListenerManager subsystem, Path file, String handle, Channel channel)
                throws IOException {
        if (!(channel instanceof FileChannel)) {
            throw new StreamCorruptedException("Non file channel to sync: " + channel);
        }

        ((FileChannel) channel).force(true);
    }

    /**
     * Called when a new directory stream is requested
     *
     * @param session The {@link ServerSession} through which the request was received
     * @param subsystem The SFTP subsystem instance that manages the session
     * @param dir The requested <U>local</U> directory
     * @param handle The assigned directory handle through which the remote peer references this directory
     * @return The opened {@link DirectoryStream}
     * @throws IOException If failed to open
     */
    default DirectoryStream<Path> openDirectory(
            ServerSession session, SftpEventListenerManager subsystem, Path dir, String handle)
                throws IOException {
        return Files.newDirectoryStream(dir);
    }
}
