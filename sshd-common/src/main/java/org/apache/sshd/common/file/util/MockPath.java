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

package org.apache.sshd.common.file.util;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.WatchEvent.Kind;
import java.nio.file.WatchEvent.Modifier;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.Collections;
import java.util.Iterator;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class MockPath implements Path {
    private final String path;
    private final FileSystem fs;

    public MockPath(String path) {
        this.path = path;
        this.fs = new MockFileSystem(path);
    }

    @Override
    public FileSystem getFileSystem() {
        return fs;
    }

    @Override
    public boolean isAbsolute() {
        return true;
    }

    @Override
    public Path getRoot() {
        return this;
    }

    @Override
    public Path getFileName() {
        return this;
    }

    @Override
    public Path getParent() {
        return null;
    }

    @Override
    public int getNameCount() {
        return 0;
    }

    @Override
    public Path getName(int index) {
        if (index == 0) {
            return this;
        } else {
            throw new IllegalArgumentException("getName - bad index: " + index);
        }
    }

    @Override
    public Path subpath(int beginIndex, int endIndex) {
        throw new UnsupportedOperationException("subPath(" + beginIndex + "," + endIndex + ") N/A");
    }

    @Override
    public boolean startsWith(Path other) {
        return startsWith(other.toString());
    }

    @Override
    public boolean startsWith(String other) {
        return path.startsWith(other);
    }

    @Override
    public boolean endsWith(Path other) {
        return endsWith(other.toString());
    }

    @Override
    public boolean endsWith(String other) {
        return path.endsWith(other);
    }

    @Override
    public Path normalize() {
        return this;
    }

    @Override
    public Path resolve(Path other) {
        return resolve(other.toString());
    }

    @Override
    public Path resolve(String other) {
        throw new UnsupportedOperationException("resolve(" + other + ") N/A");
    }

    @Override
    public Path resolveSibling(Path other) {
        return resolveSibling(other.toString());
    }

    @Override
    public Path resolveSibling(String other) {
        throw new UnsupportedOperationException("resolveSibling(" + other + ") N/A");
    }

    @Override
    public Path relativize(Path other) {
        throw new UnsupportedOperationException("relativize(" + other + ") N/A");
    }

    @Override
    public URI toUri() {
        throw new UnsupportedOperationException("toUri() N/A");
    }

    @Override
    public Path toAbsolutePath() {
        return this;
    }

    @Override
    public Path toRealPath(LinkOption... options) throws IOException {
        return this;
    }

    @Override
    public File toFile() {
        throw new UnsupportedOperationException("toFile() N/A");
    }

    @Override
    public WatchKey register(WatchService watcher, Kind<?>... events) throws IOException {
        return register(watcher, events, (Modifier[]) null);
    }

    @Override
    public WatchKey register(WatchService watcher, Kind<?>[] events, Modifier... modifiers) throws IOException {
        throw new IOException("register(" + path + ") N/A");
    }

    @Override
    public Iterator<Path> iterator() {
        return Collections.<Path> singleton(this).iterator();
    }

    @Override
    public int compareTo(Path other) {
        return path.compareTo(other.toString());
    }

    @Override
    public String toString() {
        return path;
    }

}
