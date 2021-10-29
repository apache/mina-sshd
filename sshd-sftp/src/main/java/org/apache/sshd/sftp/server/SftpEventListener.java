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

package org.apache.sshd.sftp.server;

import java.io.IOException;
import java.nio.file.CopyOption;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Map;

import org.apache.sshd.common.util.SshdEventListener;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.sftp.common.SftpConstants;

/**
 * Can be used register for SFTP events. <B>Note:</B> it does not expose the entire set of available SFTP commands and
 * responses (e.g., no reports for initialization, extensions, parameters re-negotiation, etc...);
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SftpEventListener extends SshdEventListener {

    /**
     * Called when a SFTP request has been received before it is processed.
     *
     * @param  session     The {@link ServerSession} through which the request was received
     * @param  type        The request type; one of the {@code SSH_FXP_*} constants from {@link SftpConstants}
     * @param  id          The id received with the request
     * @throws IOException If the request shall generate an error response. Throwing an exception for
     *                     {@code type = }{@link SftpConstants#SSH_FXP_INIT} closes the session.
     */
    default void received(ServerSession session, int type, int id) throws IOException {
        // empty
    }

    /**
     * Called when a SFTP extension request {@link SftpConstants#SSH_FXP_EXTENDED} has been received before it is
     * processed.
     *
     * @param  session     The {@link ServerSession} through which the request was received
     * @param  extension   The extension request received; one of the {@code SSH_EXT_*} constants from
     *                     {@link SftpConstants}
     * @param  id          The id received with the request
     * @throws IOException If the request shall generate an error response.
     */
    default void receivedExtension(ServerSession session, String extension, int id) throws IOException {
        // empty
    }

    /**
     * Called when the SFTP protocol has been initialized
     *
     * @param  session     The {@link ServerSession} through which the request was handled
     * @param  version     The negotiated SFTP version
     * @throws IOException If failed to handle the call
     */
    default void initialized(ServerSession session, int version) throws IOException {
        // ignored
    }

    /**
     * Called when subsystem is exiting due to being destroyed
     *
     * @param  session     The associated {@link ServerSession}
     * @param  handle      The file / directory {@link Handle} being closed due to the exit
     * @throws IOException If failed to handle the call
     */
    default void exiting(ServerSession session, Handle handle) throws IOException {
        // ignored
    }

    /**
     * Called when subsystem is destroyed since it was closed
     *
     * @param  session     The associated {@link ServerSession}
     * @throws IOException If failed to handle the call
     */
    default void destroying(ServerSession session) throws IOException {
        // ignored
    }

    /**
     * Specified file / directory is being opened
     *
     * @param  session      The {@link ServerSession} through which the request was handled
     * @param  remoteHandle The (opaque) assigned handle for the file / directory
     * @param  localHandle  The associated file / directory {@link Handle}
     * @throws IOException  If failed to handle the call
     */
    default void opening(ServerSession session, String remoteHandle, Handle localHandle)
            throws IOException {
        // ignored
    }

    /**
     * Specified file / directory has been opened
     *
     * @param  session      The {@link ServerSession} through which the request was handled
     * @param  remoteHandle The (opaque) assigned handle for the file / directory
     * @param  localHandle  The associated file / directory {@link Handle}
     * @throws IOException  If failed to handle the call
     */
    default void open(ServerSession session, String remoteHandle, Handle localHandle)
            throws IOException {
        // ignored
    }

    /**
     * Specified file / directory could not be opened - <B>Note:</B> this call may occur without
     * {@link #opening(ServerSession, String, Handle)} ever having been called
     *
     * @param  session     The {@link ServerSession} through which the request was handled
     * @param  remotePath  The path that was specified in the command
     * @param  localPath   The matching resolved local path
     * @param  isDirectory Whether this was a folder or a file
     * @param  thrown      Non-{@code null} reason for the failure
     * @throws IOException If failed to handle the call
     */
    default void openFailed(
            ServerSession session, String remotePath, Path localPath, boolean isDirectory, Throwable thrown)
            throws IOException {
        // ignored
    }

    /**
     * About to read entries from a directory - <B>Note:</B> might not be the 1st time it is called for the directory in
     * case several iterations are required in order to go through all the entries in the directory
     *
     * @param  session      The {@link ServerSession} through which the request was handled
     * @param  remoteHandle The (opaque) assigned handle for the directory
     * @param  localHandle  The associated {@link DirectoryHandle}
     * @throws IOException  If failed to handle the call
     * @see                 #readEntries(ServerSession, String, DirectoryHandle, Map) readEntries
     */
    default void readingEntries(
            ServerSession session, String remoteHandle, DirectoryHandle localHandle)
            throws IOException {
        // ignored
    }

    /**
     * Result of reading entries from a directory - <B>Note:</B> it may be a <U>partial</U> result if the directory
     * contains more entries than can be accommodated in the response
     *
     * @param  session      The {@link ServerSession} through which the request was handled
     * @param  remoteHandle The (opaque) assigned handle for the directory
     * @param  localHandle  The associated {@link DirectoryHandle}
     * @param  entries      A {@link Map} of the listed entries - key = short name, value = {@link Path} of the
     *                      sub-entry
     * @throws IOException  If failed to handle the call
     */
    default void readEntries(
            ServerSession session, String remoteHandle, DirectoryHandle localHandle, Map<String, Path> entries)
            throws IOException {
        // ignored
    }

    /**
     * Preparing to read from a file
     *
     * @param  session      The {@link ServerSession} through which the request was handled
     * @param  remoteHandle The (opaque) assigned handle for the file
     * @param  localHandle  The associated {@link FileHandle}
     * @param  offset       Offset in file from which to read
     * @param  data         Buffer holding the read data
     * @param  dataOffset   Offset of read data in buffer
     * @param  dataLen      Requested read length
     * @throws IOException  If failed to handle the call
     */
    default void reading(
            ServerSession session, String remoteHandle, FileHandle localHandle,
            long offset, byte[] data, int dataOffset, int dataLen)
            throws IOException {
        // ignored
    }

    /**
     * Result of reading from a file
     *
     * @param  session      The {@link ServerSession} through which the request was handled
     * @param  remoteHandle The (opaque) assigned handle for the file
     * @param  localHandle  The associated {@link FileHandle}
     * @param  offset       Offset in file from which to read
     * @param  data         Buffer holding the read data
     * @param  dataOffset   Offset of read data in buffer
     * @param  dataLen      Requested read length
     * @param  readLen      Actual read length - negative if thrown exception provided
     * @param  thrown       Non-{@code null} if read failed due to this exception
     * @throws IOException  If failed to handle the call
     */
    @SuppressWarnings("checkstyle:ParameterNumber")
    default void read(
            ServerSession session, String remoteHandle, FileHandle localHandle,
            long offset, byte[] data, int dataOffset, int dataLen, int readLen, Throwable thrown)
            throws IOException {
        // ignored
    }

    /**
     * Preparing to write to file
     *
     * @param  session      The {@link ServerSession} through which the request was handled
     * @param  remoteHandle The (opaque) assigned handle for the file
     * @param  localHandle  The associated {@link FileHandle}
     * @param  offset       Offset in file to which to write
     * @param  data         Buffer holding the written data
     * @param  dataOffset   Offset of write data in buffer
     * @param  dataLen      Requested write length
     * @throws IOException  If failed to handle the call
     */
    default void writing(
            ServerSession session, String remoteHandle, FileHandle localHandle,
            long offset, byte[] data, int dataOffset, int dataLen)
            throws IOException {
        // ignored
    }

    /**
     * Finished to writing to file
     *
     * @param  session      The {@link ServerSession} through which the request was handled
     * @param  remoteHandle The (opaque) assigned handle for the file
     * @param  localHandle  The associated {@link FileHandle}
     * @param  offset       Offset in file to which to write
     * @param  data         Buffer holding the written data
     * @param  dataOffset   Offset of write data in buffer
     * @param  dataLen      Requested write length
     * @param  thrown       The reason for failing to write - {@code null} if successful
     * @throws IOException  If failed to handle the call
     */
    default void written(
            ServerSession session, String remoteHandle, FileHandle localHandle,
            long offset, byte[] data, int dataOffset, int dataLen, Throwable thrown)
            throws IOException {
        // ignored
    }

    /**
     * Called <U>prior</U> to blocking a file section
     *
     * @param  session      The {@link ServerSession} through which the request was handled
     * @param  remoteHandle The (opaque) assigned handle for the file
     * @param  localHandle  The associated {@link FileHandle}
     * @param  offset       Offset in file for locking
     * @param  length       Section size for locking
     * @param  mask         Lock mask flags - see {@code SSH_FXP_BLOCK} message
     * @throws IOException  If failed to handle the call
     * @see                 #blocked(ServerSession, String, FileHandle, long, long, int, Throwable)
     */
    default void blocking(
            ServerSession session, String remoteHandle, FileHandle localHandle,
            long offset, long length, int mask)
            throws IOException {
        // ignored
    }

    /**
     * Called <U>after</U> blocking a file section
     *
     * @param  session      The {@link ServerSession} through which the request was handled
     * @param  remoteHandle The (opaque) assigned handle for the file
     * @param  localHandle  The associated {@link FileHandle}
     * @param  offset       Offset in file for locking
     * @param  length       Section size for locking
     * @param  mask         Lock mask flags - see {@code SSH_FXP_BLOCK} message
     * @param  thrown       If not-{@code null} then the reason for the failure to execute
     * @throws IOException  If failed to handle the call
     */
    default void blocked(
            ServerSession session, String remoteHandle, FileHandle localHandle,
            long offset, long length, int mask, Throwable thrown)
            throws IOException {
        // ignored
    }

    /**
     * Called <U>prior</U> to un-blocking a file section
     *
     * @param  session      The {@link ServerSession} through which the request was handled
     * @param  remoteHandle The (opaque) assigned handle for the file
     * @param  localHandle  The associated {@link FileHandle}
     * @param  offset       Offset in file for un-locking
     * @param  length       Section size for un-locking
     * @throws IOException  If failed to handle the call
     */
    default void unblocking(
            ServerSession session, String remoteHandle, FileHandle localHandle, long offset, long length)
            throws IOException {
        // ignored
    }

    /**
     * Called <U>prior</U> to un-blocking a file section
     *
     * @param  session      The {@link ServerSession} through which the request was handled
     * @param  remoteHandle The (opaque) assigned handle for the file
     * @param  localHandle  The associated {@link FileHandle}
     * @param  offset       Offset in file for un-locking
     * @param  length       Section size for un-locking
     * @param  thrown       If not-{@code null} then the reason for the failure to execute
     * @throws IOException  If failed to handle the call
     */
    default void unblocked(
            ServerSession session, String remoteHandle, FileHandle localHandle,
            long offset, long length, Throwable thrown)
            throws IOException {
        // ignored
    }

    /**
     * Specified file / directory about to be closed
     *
     * @param  session      The {@link ServerSession} through which the request was handled
     * @param  remoteHandle The (opaque) assigned handle for the file / directory
     * @param  localHandle  The associated file / directory {@link Handle}
     * @throws IOException  If failed to handle the call
     */
    default void closing(ServerSession session, String remoteHandle, Handle localHandle)
            throws IOException {
        // ignored
    }

    /**
     * Specified file / directory has been closed
     *
     * @param  session      The {@link ServerSession} through which the request was handled
     * @param  remoteHandle The (opaque) assigned handle for the file / directory
     * @param  localHandle  The associated file / directory {@link Handle}
     * @param  thrown       If not-{@code null} then the reason for the failure to execute
     * @throws IOException  If failed to handle the call
     */
    default void closed(
            ServerSession session, String remoteHandle, Handle localHandle, Throwable thrown)
            throws IOException {
        // ignored
    }

    /**
     * Called <U>prior</U> to creating a directory
     *
     * @param  session     The {@link ServerSession} through which the request was handled
     * @param  path        Directory {@link Path} to be created
     * @param  attrs       Requested associated attributes to set
     * @throws IOException If failed to handle the call
     * @see                #created(ServerSession, Path, Map, Throwable)
     */
    default void creating(ServerSession session, Path path, Map<String, ?> attrs)
            throws IOException {
        // ignored
    }

    /**
     * Called <U>after</U> creating a directory
     *
     * @param  session     The {@link ServerSession} through which the request was handled
     * @param  path        Directory {@link Path} to be created
     * @param  attrs       Requested associated attributes to set
     * @param  thrown      If not-{@code null} then the reason for the failure to execute
     * @throws IOException If failed to handle the call
     */
    default void created(ServerSession session, Path path, Map<String, ?> attrs, Throwable thrown)
            throws IOException {
        // ignored
    }

    /**
     * Called <U>prior</U> to renaming a file / directory
     *
     * @param  session     The {@link ServerSession} through which the request was handled
     * @param  srcPath     The source {@link Path}
     * @param  dstPath     The target {@link Path}
     * @param  opts        The resolved renaming options
     * @throws IOException If failed to handle the call
     * @see                #moved(ServerSession, Path, Path, Collection, Throwable)
     */
    default void moving(
            ServerSession session, Path srcPath, Path dstPath, Collection<CopyOption> opts)
            throws IOException {
        // ignored
    }

    /**
     * Called <U>after</U> renaming a file / directory
     *
     * @param  session     The {@link ServerSession} through which the request was handled
     * @param  srcPath     The source {@link Path}
     * @param  dstPath     The target {@link Path}
     * @param  opts        The resolved renaming options
     * @param  thrown      If not-{@code null} then the reason for the failure to execute
     * @throws IOException If failed to handle the call
     */
    default void moved(
            ServerSession session, Path srcPath, Path dstPath, Collection<CopyOption> opts, Throwable thrown)
            throws IOException {
        // ignored
    }

    /**
     * Called <U>prior</U> to removing a file
     *
     * @param  session     The {@link ServerSession} through which the request was handled
     * @param  path        The {@link Path} about to be removed
     * @param  isDirectory Whether this is a folder or a file
     * @throws IOException If failed to handle the call
     * @see                #removed(ServerSession, Path, boolean, Throwable)
     */
    default void removing(ServerSession session, Path path, boolean isDirectory) throws IOException {
        // ignored
    }

    /**
     * Called <U>after</U> a file has been removed
     *
     * @param  session     The {@link ServerSession} through which the request was handled
     * @param  path        The {@link Path} to be removed
     * @param  isDirectory Whether this was a folder or a file
     * @param  thrown      If not-{@code null} then the reason for the failure to execute
     * @throws IOException If failed to handle the call
     */
    default void removed(
            ServerSession session, Path path, boolean isDirectory, Throwable thrown)
            throws IOException {
        // ignored
    }

    /**
     * Called <U>prior</U> to creating a link
     *
     * @param  session     The {@link ServerSession} through which the request was handled
     * @param  source      The source {@link Path}
     * @param  target      The target {@link Path}
     * @param  symLink     {@code true} = symbolic link
     * @throws IOException If failed to handle the call
     * @see                #linked(ServerSession, Path, Path, boolean, Throwable)
     */
    default void linking(ServerSession session, Path source, Path target, boolean symLink)
            throws IOException {
        // ignored
    }

    /**
     * Called <U>after</U> creating a link
     *
     * @param  session     The {@link ServerSession} through which the request was handled
     * @param  source      The source {@link Path}
     * @param  target      The target {@link Path}
     * @param  symLink     {@code true} = symbolic link
     * @param  thrown      If not-{@code null} then the reason for the failure to execute
     * @throws IOException If failed to handle the call
     */
    default void linked(
            ServerSession session, Path source, Path target, boolean symLink, Throwable thrown)
            throws IOException {
        // ignored
    }

    /**
     * Called <U>prior</U> to modifying the attributes of a file / directory
     *
     * @param  session     The {@link ServerSession} through which the request was handled
     * @param  path        The file / directory {@link Path} to be modified
     * @param  attrs       The attributes {@link Map} - names and values depend on the O/S, view, type, etc...
     * @throws IOException If failed to handle the call
     * @see                #modifiedAttributes(ServerSession, Path, Map, Throwable)
     */
    default void modifyingAttributes(ServerSession session, Path path, Map<String, ?> attrs)
            throws IOException {
        // ignored
    }

    /**
     * Called <U>after</U> modifying the attributes of a file / directory
     *
     * @param  session     The {@link ServerSession} through which the request was handled
     * @param  path        The file / directory {@link Path} to be modified
     * @param  attrs       The attributes {@link Map} - names and values depend on the O/S, view, type, etc...
     * @param  thrown      If not-{@code null} then the reason for the failure to execute
     * @throws IOException If failed to handle the call
     */
    default void modifiedAttributes(
            ServerSession session, Path path, Map<String, ?> attrs, Throwable thrown)
            throws IOException {
        // ignored
    }

    static <L extends SftpEventListener> L validateListener(L listener) {
        return SshdEventListener.validateListener(listener, SftpEventListener.class.getSimpleName());
    }
}
