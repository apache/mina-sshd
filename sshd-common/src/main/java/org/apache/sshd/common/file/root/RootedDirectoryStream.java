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
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.util.Iterator;

/**
 * secure directory stream proxy for a {@link RootedFileSystem}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class RootedDirectoryStream implements DirectoryStream<Path> {
    protected final RootedFileSystem rfs;
    protected final DirectoryStream<Path> delegate;

    RootedDirectoryStream(RootedFileSystem rfs, DirectoryStream<Path> delegate) {
        this.rfs = rfs;
        this.delegate = delegate;
    }

    @Override
    public Iterator<Path> iterator() {
        return root(rfs, delegate.iterator());
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }

    protected Iterator<Path> root(RootedFileSystem rfs, Iterator<Path> iter) {
        return new Iterator<Path>() {
            @Override
            public boolean hasNext() {
                return iter.hasNext();
            }

            @Override
            public Path next() {
                return rfs.provider().root(rfs, iter.next());
            }
        };
    }
}
