/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

/**
 * This is the file abstraction used by the server.
 *
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public interface SshFile {

    /**
     * Get the full path from the base directory of the FileSystemView.
     * @return a path where the path separator is '/' (even if the operating system
     *     uses another character as path separator).
     */
    String getAbsolutePath();

    /**
     * Get the file name of the file
     * @return the last part of the file path (the part after the last '/').
     */
    String getName();

    /**
     * Get the owner name of the file
     * @return the name of the owner.
     */
    String getOwner();

    /**
     * Is it a directory?
     * @return true if the {@link SshFile} is a directory
     */
    boolean isDirectory();

    /**
     * Is it a file?
     * @return true if the {@link SshFile} is a file, false if it is a directory
     */
    boolean isFile();

    /**
     * Does this file exists?
     * @return true if the {@link SshFile} exists
     */
    boolean doesExist();

    /**
     * Has read permission?
     * @return true if the {@link SshFile} is readable by the user
     */
    boolean isReadable();

    /**
     * Has write permission?
     * @return true if the {@link SshFile} is writable by the user
     */
    boolean isWritable();

    /**
     * Has exec permission?
     * @return true if the {@link SshFile} is executable by the user
     */
    boolean isExecutable();

    /**
     * Has delete permission?
     * @return true if the {@link SshFile} is removable by the user
     */
    boolean isRemovable();

    /**
     * Get the immediate parent. Returns the root directory if the current file is the root.
     * @return
     */
    SshFile getParentFile();

    /**
     * Get last modified time in UTC.
     * @return The timestamp of the last modified time for the {@link SshFile}
     */
    long getLastModified();

    /**
     * Set the last modified time stamp of a file
     * @param time The last modified time, in milliseconds since the epoch. See {@link java.io.File#setLastModified(long)}.
     */
    boolean setLastModified(long time);
    
    /**
     * Get file size.
     * @return The size of the {@link SshFile} in bytes
     */
    long getSize();

    /**
     * Create directory.
     * @return true if the operation was successful
     */
    boolean mkdir();

    /**
     * Delete file.
     * @return true if the operation was successful
     */
    boolean delete();

    /**
     * Create the file.
     * @return true if the file has been created and false if it already exist
     * @throws java.io.IOException if something wrong happen
     */
    boolean create() throws IOException;

    /**
     * Truncate the file to length 0.
     * @throws java.io.IOException if something wrong happen
     */
    void truncate() throws IOException;

    /**
     * Move file.
     * @param destination The target {@link SshFile} to move the current {@link SshFile} to
     * @return true if the operation was successful
     */
    boolean move(SshFile destination);

    /**
     * List file objects. If not a directory or does not exist, null will be
     * returned. Files must be returned in alphabetical order.
     * List must be immutable.
     * @return The {@link java.util.List} of {@link SshFile}s
     */
    List<SshFile> listSshFiles();

    /**
     * Create output stream for writing. 
     * @param offset The number of bytes at where to start writing.
     *      If the file is not random accessible,
     *      any offset other than zero will throw an exception.
     * @return An {@link java.io.OutputStream} used to write to the {@link SshFile}
     * @throws java.io.IOException 
     */
    OutputStream createOutputStream(long offset) throws IOException;

    /**
     * Create input stream for reading. 
     * @param offset The number of bytes of where to start reading. 
     *          If the file is not random accessible,
     *          any offset other than zero will throw an exception.
     * @return An {@link java.io.InputStream} used to read the {@link SshFile}
     * @throws java.io.IOException 
     */
    InputStream createInputStream(long offset) throws IOException;

    /**
     * Handle post-handle-close functionality.
     * @throws IOException
     */
    void handleClose() throws IOException;
}
