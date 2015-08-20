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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;
import java.util.Set;

import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LocalFileScpSourceStreamResolver extends AbstractLoggingBean implements ScpSourceStreamResolver {
    private final Path path;
    private final Path name;
    private final Set<PosixFilePermission> perms;
    private final long size;
    private final ScpTimestamp time;

    public LocalFileScpSourceStreamResolver(Path path) throws IOException {
        this.path = ValidateUtils.checkNotNull(path, "No path specified");
        this.name = path.getFileName();
        this.perms = IoUtils.getPermissions(path);

        BasicFileAttributes basic = Files.getFileAttributeView(path, BasicFileAttributeView.class).readAttributes();
        this.size = basic.size();
        this.time = new ScpTimestamp(basic.lastModifiedTime().toMillis(), basic.lastAccessTime().toMillis());
    }

    @Override
    public String getFileName() throws IOException {
        return name.toString();
    }

    @Override
    public Collection<PosixFilePermission> getPermissions() throws IOException {
        return perms;
    }

    @Override
    public ScpTimestamp getTimestamp() throws IOException {
        return time;
    }

    @Override
    public long getSize() throws IOException {
        return size;
    }

    @Override
    public Path getEventListenerFilePath() {
        return path;
    }

    @Override
    public InputStream resolveSourceStream() throws IOException {
        return Files.newInputStream(getEventListenerFilePath());
    }

    @Override
    public String toString() {
        return String.valueOf(getEventListenerFilePath());
    }
}
