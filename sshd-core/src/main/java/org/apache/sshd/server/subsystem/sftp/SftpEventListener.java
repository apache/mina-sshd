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

import java.nio.file.CopyOption;
import java.nio.file.Path;
import java.util.Collection;
import java.util.EventListener;
import java.util.Map;

import org.apache.sshd.server.session.ServerSession;

/**
 * Can be used register for SFTP events. <B>Note:</B> it does not expose
 * the entire set of available SFTP commands and responses (e.g., no reports
 * for initialization, extensions, parameters re-negotiation, etc...);
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SftpEventListener extends EventListener {
    /**
     * Called when the SFTP protocol has been initialized
     *
     * @param session The {@link ServerSession} through which the request was handled
     * @param version The negotiated SFTP version
     */
    void initialized(ServerSession session, int version);

    /**
     * Called when subsystem is destroyed since it was closed
     *
     * @param session The associated {@link ServerSession}
     */
    void destroying(ServerSession session);

    /**
     * Specified file / directory has been opened
     *
     * @param session      The {@link ServerSession} through which the request was handled
     * @param remoteHandle The (opaque) assigned handle for the file / directory
     * @param localHandle  The associated file / directory {@link Handle}
     */
    void open(ServerSession session, String remoteHandle, Handle localHandle);

    /**
     * Result of reading entries from a directory - <B>Note:</B> it may be a
     * <U>partial</U> result if the directory contains more entries than can
     * be accommodated in the response
     *
     * @param session      The {@link ServerSession} through which the request was handled
     * @param remoteHandle The (opaque) assigned handle for the directory
     * @param localHandle  The associated {@link DirectoryHandle}
     * @param entries      A {@link Map} of the listed entries - key = short name,
     *                     value = {@link Path} of the sub-entry
     */
    void read(ServerSession session, String remoteHandle, DirectoryHandle localHandle, Map<String, Path> entries);

    /**
     * Result of reading from a file
     *
     * @param session      The {@link ServerSession} through which the request was handled
     * @param remoteHandle The (opaque) assigned handle for the file
     * @param localHandle  The associated {@link FileHandle}
     * @param offset       Offset in file from which to read
     * @param data         Buffer holding the read data
     * @param dataOffset   Offset of read data in buffer
     * @param dataLen      Requested read length
     * @param readLen      Actual read length
     */
    void read(ServerSession session, String remoteHandle, FileHandle localHandle,
              long offset, byte[] data, int dataOffset, int dataLen, int readLen);

    /**
     * Result of writing to a file
     *
     * @param session      The {@link ServerSession} through which the request was handled
     * @param remoteHandle The (opaque) assigned handle for the file
     * @param localHandle  The associated {@link FileHandle}
     * @param offset       Offset in file to which to write
     * @param data         Buffer holding the written data
     * @param dataOffset   Offset of write data in buffer
     * @param dataLen      Requested write length
     */
    void write(ServerSession session, String remoteHandle, FileHandle localHandle,
               long offset, byte[] data, int dataOffset, int dataLen);

    /**
     * Called <U>prior</U> to blocking a file section
     *
     * @param session      The {@link ServerSession} through which the request was handled
     * @param remoteHandle The (opaque) assigned handle for the file
     * @param localHandle  The associated {@link FileHandle}
     * @param offset       Offset in file for locking
     * @param length       Section size for locking
     * @param mask         Lock mask flags - see {@code SSH_FXP_BLOCK} message
     * @see #blocked(ServerSession, String, FileHandle, long, long, int, Throwable)
     */
    void blocking(ServerSession session, String remoteHandle, FileHandle localHandle, long offset, long length, int mask);

    /**
     * Called <U>after</U> blocking a file section
     *
     * @param session      The {@link ServerSession} through which the request was handled
     * @param remoteHandle The (opaque) assigned handle for the file
     * @param localHandle  The associated {@link FileHandle}
     * @param offset       Offset in file for locking
     * @param length       Section size for locking
     * @param mask         Lock mask flags - see {@code SSH_FXP_BLOCK} message
     * @param thrown       If not-{@code null} then the reason for the failure to execute
     */
    void blocked(ServerSession session, String remoteHandle, FileHandle localHandle, long offset, long length, int mask, Throwable thrown);

    /**
     * Called <U>prior</U> to un-blocking a file section
     *
     * @param session      The {@link ServerSession} through which the request was handled
     * @param remoteHandle The (opaque) assigned handle for the file
     * @param localHandle  The associated {@link FileHandle}
     * @param offset       Offset in file for un-locking
     * @param length       Section size for un-locking
     */
    void unblocking(ServerSession session, String remoteHandle, FileHandle localHandle, long offset, long length);

    /**
     * Called <U>prior</U> to un-blocking a file section
     *
     * @param session      The {@link ServerSession} through which the request was handled
     * @param remoteHandle The (opaque) assigned handle for the file
     * @param localHandle  The associated {@link FileHandle}
     * @param offset       Offset in file for un-locking
     * @param length       Section size for un-locking
     * @param result       If successful (i.e., <tt>thrown</tt> is {@code null}, then whether
     *                     section was un-blocked
     * @param thrown       If not-{@code null} then the reason for the failure to execute
     */
    void unblocked(ServerSession session, String remoteHandle, FileHandle localHandle, long offset, long length, Boolean result, Throwable thrown);

    /**
     * Specified file / directory has been closed
     *
     * @param session      The {@link ServerSession} through which the request was handled
     * @param remoteHandle The (opaque) assigned handle for the file / directory
     * @param localHandle  The associated file / directory {@link Handle}
     */
    void close(ServerSession session, String remoteHandle, Handle localHandle);

    /**
     * Called <U>prior</U> to creating a directory
     *
     * @param session The {@link ServerSession} through which the request was handled
     * @param path    Directory {@link Path} to be created
     * @param attrs   Requested associated attributes to set
     * @see #created(ServerSession, Path, Map, Throwable)
     */
    void creating(ServerSession session, Path path, Map<String, ?> attrs);

    /**
     * Called <U>after</U> creating a directory
     *
     * @param session The {@link ServerSession} through which the request was handled
     * @param path    Directory {@link Path} to be created
     * @param attrs   Requested associated attributes to set
     * @param thrown  If not-{@code null} then the reason for the failure to execute
     */
    void created(ServerSession session, Path path, Map<String, ?> attrs, Throwable thrown);

    /**
     * Called <U>prior</U> to renaming a file / directory
     *
     * @param session The {@link ServerSession} through which the request was handled
     * @param srcPath The source {@link Path}
     * @param dstPath The target {@link Path}
     * @param opts    The resolved renaming options
     * @see #moved(ServerSession, Path, Path, Collection, Throwable)
     */
    void moving(ServerSession session, Path srcPath, Path dstPath, Collection<CopyOption> opts);

    /**
     * Called <U>after</U> renaming a file / directory
     *
     * @param session The {@link ServerSession} through which the request was handled
     * @param srcPath The source {@link Path}
     * @param dstPath The target {@link Path}
     * @param opts    The resolved renaming options
     * @param thrown  If not-{@code null} then the reason for the failure to execute
     */
    void moved(ServerSession session, Path srcPath, Path dstPath, Collection<CopyOption> opts, Throwable thrown);

    /**
     * Called <U>prior</U> to removing a file / directory
     *
     * @param session The {@link ServerSession} through which the request was handled
     * @param path    The {@link Path} about to be removed
     * @see #removed(ServerSession, Path, Throwable)
     */
    void removing(ServerSession session, Path path);

    /**
     * Called <U>after</U> a file / directory has been removed
     *
     * @param session The {@link ServerSession} through which the request was handled
     * @param path    The {@link Path} to be removed
     * @param thrown  If not-{@code null} then the reason for the failure to execute
     */
    void removed(ServerSession session, Path path, Throwable thrown);

    /**
     * Called <U>prior</U> to creating a link
     *
     * @param session The {@link ServerSession} through which the request was handled
     * @param source  The source {@link Path}
     * @param target  The target {@link Path}
     * @param symLink {@code true} = symbolic link
     * @see #linked(ServerSession, Path, Path, boolean, Throwable)
     */
    void linking(ServerSession session, Path source, Path target, boolean symLink);

    /**
     * Called <U>after</U> creating a link
     *
     * @param session The {@link ServerSession} through which the request was handled
     * @param source  The source {@link Path}
     * @param target  The target {@link Path}
     * @param symLink {@code true} = symbolic link
     * @param thrown  If not-{@code null} then the reason for the failure to execute
     */
    void linked(ServerSession session, Path source, Path target, boolean symLink, Throwable thrown);

    /**
     * Called <U>prior</U> to modifying the attributes of a file / directory
     *
     * @param session The {@link ServerSession} through which the request was handled
     * @param path    The file / directory {@link Path} to be modified
     * @param attrs   The attributes {@link Map} - names and values depend on the
     *                O/S, view, type, etc...
     * @see #modifiedAttributes(ServerSession, Path, Map, Throwable)
     */
    void modifyingAttributes(ServerSession session, Path path, Map<String, ?> attrs);

    /**
     * Called <U>after</U> modifying the attributes of a file / directory
     *
     * @param session The {@link ServerSession} through which the request was handled
     * @param path    The file / directory {@link Path} to be modified
     * @param attrs   The attributes {@link Map} - names and values depend on the
     *                O/S, view, type, etc...
     * @param thrown  If not-{@code null} then the reason for the failure to execute
     */
    void modifiedAttributes(ServerSession session, Path path, Map<String, ?> attrs, Throwable thrown);
}
