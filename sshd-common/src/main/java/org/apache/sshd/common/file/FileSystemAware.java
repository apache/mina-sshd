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
package org.apache.sshd.common.file;

import java.io.IOException;
import java.nio.file.FileSystem;

import org.apache.sshd.common.session.SessionContext;

/**
 * Interface that can be implemented by a command to be able to access the file system in which this command will be
 * used.
 */
@FunctionalInterface
public interface FileSystemAware {
    /**
     * Sets the {@link FileSystemFactory} used to create the {@link FileSystem} to be used by the session
     *
     * @param  factory     The factory instance
     * @param  session     The {@link SessionContext}
     * @throws IOException If failed to resolve/create the file system
     * @see                #setFileSystem(FileSystem)
     */
    default void setFileSystemFactory(
            FileSystemFactory factory, SessionContext session)
            throws IOException {
        FileSystem fs = factory.createFileSystem(session);
        setFileSystem(fs);
    }

    /**
     * Set the file system in which this shell will be executed.
     *
     * @param fileSystem the file system
     */
    void setFileSystem(FileSystem fileSystem);
}
