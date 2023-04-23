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
package org.apache.sshd.common.file.root;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.util.Set;

/**
 * A secure directory stream proxy for a {@link RootedFileSystem}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class RootedSecureDirectoryStream extends RootedDirectoryStream implements SecureDirectoryStream<Path> {

    RootedSecureDirectoryStream(RootedFileSystem rfs, SecureDirectoryStream<Path> delegate) {
        super(rfs, delegate);
    }

    @Override
    public SecureDirectoryStream<Path> newDirectoryStream(Path path, LinkOption... options) throws IOException {
        return new RootedSecureDirectoryStream(rfs, delegate().newDirectoryStream(fixPath(path), options));
    }

    protected Path fixPath(Path p) {
        if (p.isAbsolute()) {
            return rfs.provider().unroot(p);
        }

        // convert to root fs path.
        // Note: this IS able to go below the root directory by design - a way to break out of chroot.
        // Be very cautious using this.
        return rfs.getRootFileSystem().getPath(p.toString());
    }

    @Override
    public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs)
            throws IOException {
        return delegate().newByteChannel(fixPath(path), options, attrs);
    }

    @Override
    public void deleteFile(Path path) throws IOException {
        delegate().deleteFile(fixPath(path));
    }

    @Override
    public void deleteDirectory(Path path) throws IOException {
        delegate().deleteDirectory(fixPath(path));
    }

    @Override
    public void move(Path srcpath, SecureDirectoryStream<Path> targetdir, Path targetpath) throws IOException {
        delegate().move(fixPath(srcpath), targetdir, targetpath);
    }

    @Override
    public <V extends FileAttributeView> V getFileAttributeView(Class<V> type) {
        return delegate().getFileAttributeView(type);
    }

    @Override
    public <V extends FileAttributeView> V getFileAttributeView(Path path, Class<V> type, LinkOption... options) {
        return delegate().getFileAttributeView(path, type, options);
    }

    private SecureDirectoryStream<Path> delegate() {
        return (SecureDirectoryStream<Path>) delegate;
    }
}
