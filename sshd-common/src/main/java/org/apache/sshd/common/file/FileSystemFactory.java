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
import java.nio.file.Path;

import org.apache.sshd.common.session.SessionContext;

/**
 * Factory for file system implementations - it returns the file system for user.
 *
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public interface FileSystemFactory {
    /**
     *
     * @param  session     The session created for the user
     * @return             The recommended user home directory - {@code null} if none
     * @throws IOException If failed to resolve user's home directory
     */
    Path getUserHomeDir(SessionContext session) throws IOException;

    /**
     * Create user specific file system.
     *
     * @param  session     The session created for the user
     * @return             The current {@link FileSystem} for the provided session
     * @throws IOException if the file system can not be created
     */
    FileSystem createFileSystem(SessionContext session) throws IOException;
}
