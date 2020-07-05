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

package org.apache.sshd.common.file.nonefs;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Path;

import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.session.SessionContext;

/**
 * Provides an &quot;empty&quot; file system that has no files/folders and throws exceptions on any attempt to access a
 * file/folder on it
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class NoneFileSystemFactory implements FileSystemFactory {
    public static final NoneFileSystemFactory INSTANCE = new NoneFileSystemFactory();

    public NoneFileSystemFactory() {
        super();
    }

    @Override
    public Path getUserHomeDir(SessionContext session) throws IOException {
        return null;
    }

    @Override
    public FileSystem createFileSystem(SessionContext session) throws IOException {
        return NoneFileSystem.INSTANCE;
    }
}
