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
package org.apache.sshd.common.file.virtualfs;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.sshd.common.Session;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.FileSystemView;
import org.apache.sshd.common.file.nativefs.NativeFileSystemView;

/**
 * SSHd file system factory to reduce the visibility to a physical folder.
 */
public class VirtualFileSystemFactory implements FileSystemFactory {

    private String defaultHomeDir;
    private final Map<String, String> homeDirs = new ConcurrentHashMap<String, String>();

    public VirtualFileSystemFactory() {
    }

    public VirtualFileSystemFactory(String defaultHomeDir) {
        this.defaultHomeDir = defaultHomeDir;
    }

    public void setDefaultHomeDir(String defaultHomeDir) {
        this.defaultHomeDir = defaultHomeDir;
    }

    public String getDefaultHomeDir() {
        return defaultHomeDir;
    }

    public void setUserHomeDir(String userName, String userHomeDir) {
        homeDirs.put(userName, userHomeDir);
    }

    public String getUserHomeDir(String userName) {
        return homeDirs.get(userName);
    }

    protected String computeRootDir(String userName) {
        String homeDir = homeDirs.get(userName);
        if (homeDir == null) {
            homeDir = defaultHomeDir;
        }
        if (homeDir == null) {
            throw new IllegalStateException("No home directory for user " + userName);
        }
        return homeDir;
    }

    public FileSystemView createFileSystemView(Session session) {
        String dir = computeRootDir(session.getUsername());
        Map<String, String> roots = new HashMap<String, String>();
        roots.put("/", dir);
        return new NativeFileSystemView(session.getUsername(), roots, "/", '/', false);
    }

}
