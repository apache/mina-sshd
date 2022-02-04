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
package org.apache.sshd.sftp.client.impl;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import org.apache.sshd.common.util.io.functors.IOFunction;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.fs.SftpFileSystem;
import org.apache.sshd.sftp.client.fs.SftpPath;

/**
 * An {@link SftpPath} that can cache {@code SftpClient.Attributes}.
 */
public class SftpPathImpl extends SftpPath {

    private SftpClient.Attributes attributes;

    private int cachingLevel;

    public SftpPathImpl(SftpFileSystem fileSystem, String root, List<String> names) {
        super(fileSystem, root, names);
    }

    /**
     * {@link SftpPath} instances can cache SFTP {@code SftpClient.Attributes}. Caching can be enabled by passing
     * {@code true}. If the {@link SftpPath} instance is already caching attributes, a counter is increased only. To
     * disable caching, pass {@code false}, which decreases the counter. The cache is cleared when the counter reaches
     * zero again.
     * <p>
     * Each call of {@code cacheAttributes(true)} must be matched by a call to {@code cacheAttributes(false)}. Such call
     * pairs can be nested; caching is enabled for the duration of the outermost such pair. The outermost call passing
     * {@code true} clears any possibly already cached attributes so that the next attempt to read remote attributes
     * will fetch them anew.
     * </p>
     * <p>
     * Client code should use {@link #withAttributeCache(Path, IOFunction)}, which ensures the above condition.
     * </p>
     *
     * @param doCache whether to start caching (increasing the cache level) or to stop caching (decreasing the cache
     *                level)
     * @see           #withAttributeCache(Path, IOFunction)
     */
    protected void cacheAttributes(boolean doCache) {
        if (doCache) {
            // Start caching. Clear possibly already cached data
            if (cachingLevel == 0) {
                attributes = null;
            }
            cachingLevel++;
        } else if (cachingLevel > 0) {
            // Stop caching
            cachingLevel--;
            if (cachingLevel == 0) {
                attributes = null;
            }
        } else {
            throw new IllegalStateException("SftpPathImpl.cacheAttributes(boolean) not properly nested");
        }
    }

    /**
     * Sets the cached attributes to the argument if this {@link SftpPath} instance is currently caching attributes.
     * Otherwise a no-op.
     *
     * @param attributes the {@code SftpClient.Attributes} to cache
     */
    public void cacheAttributes(SftpClient.Attributes attributes) {
        if (cachingLevel > 0) {
            setAttributes(attributes);
        }
    }

    /**
     * Unconditionally set the cached attributes, whether or not this instance's attribute cache is enabled.
     *
     * @param attributes the {@code SftpClient.Attributes} to cache
     */
    public void setAttributes(SftpClient.Attributes attributes) {
        this.attributes = attributes;
    }

    @Override
    public SftpClient.Attributes getAttributes() {
        return attributes;
    }

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
    public <T> T withAttributeCache(IOFunction<Path, T> operation) throws IOException {
        cacheAttributes(true);
        try {
            return operation.apply(this);
        } finally {
            cacheAttributes(false);
        }
    }

    /**
     * Performs the given operation with attribute caching, if the given {@link Path} can cache attributes, otherwise
     * simply executes the operation.
     *
     * @param  <T>         result type of the {@code operation}
     * @param  path        {@link Path} to operate on
     * @param  operation   to perform; may return {@code null} if it has no result
     * @return             the result of the {@code operation}
     * @throws IOException if thrown by the {@code operation}
     *
     * @see                #withAttributeCache(IOFunction)
     */
    public static <T> T withAttributeCache(Path path, IOFunction<Path, T> operation) throws IOException {
        if (path instanceof SftpPathImpl) {
            return ((SftpPathImpl) path).withAttributeCache(operation);
        }
        return operation.apply(path);
    }
}
