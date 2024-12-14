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
package org.apache.sshd.sftp.client.fs;

import java.io.IOException;
import java.nio.file.Path;

import org.apache.sshd.common.util.io.functors.IOFunction;
import org.apache.sshd.sftp.client.SftpClient;

/**
 * A mix-in interface for paths that can carry and cache file attributes of the referenced file.
 */
public interface WithFileAttributeCache extends WithFileAttributes {

    /**
     * Sets the attributes.
     *
     * @param attributes {@link SftpClient.Attributes} to set
     */
    void setAttributes(SftpClient.Attributes attributes);

    /**
     * Performs the given operation with attribute caching. If {@code SftpClient.Attributes} are fetched by the
     * operation, they will be cached and subsequently these cached attributes will be re-used for this {@link SftpPath}
     * instance throughout the operation. Calls to {@link #withAttributeCache(IOFunction)} may be nested. The cache is
     * cleared at the start and at the end of the outermost invocation.
     *
     * @param  <T>         result type of the {@code operation}
     * @param  operation   to perform; may return {@code null} if it has no result
     * @return             the result of the {@code operation}
     * @throws IOException if thrown by the {@code operation}
     */
    <T> T withAttributeCache(IOFunction<Path, T> operation) throws IOException;

    /**
     * Performs the given operation with attribute caching, if the given {@link Path} implements the
     * {@link WithFileAttributeCache} interface, otherwise simply executes the operation.
     *
     * @param  <T>         result type of the {@code operation}
     * @param  path        {@link Path} to operate on
     * @param  operation   to perform; may return {@code null} if it has no result
     * @return             the result of the {@code operation}
     * @throws IOException if thrown by the {@code operation}
     *
     * @see                #withAttributeCache(IOFunction)
     */
    static <T> T withAttributeCache(Path path, IOFunction<Path, T> operation) throws IOException {
        if (path instanceof WithFileAttributeCache) {
            return ((WithFileAttributeCache) path).withAttributeCache(operation);
        }
        return operation.apply(path);
    }

}
