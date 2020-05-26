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

package org.apache.sshd.common.util.io.resource;

import java.net.URI;
import java.net.URL;
import java.nio.file.Path;

import org.apache.sshd.common.NamedResource;

/**
 * @param  <T> Type of resource
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface IoResource<T> extends NamedResource, ResourceStreamProvider {
    /**
     * @return The type of resource being represented
     */
    Class<T> getResourceType();

    /**
     * @return The resource value serving as basis for the provided data stream
     */
    T getResourceValue();

    /**
     * Attempts to find the best wrapper for the resource
     *
     * @param  resource                      The resource object - ignored if {@code null}
     * @return                               The best wrapper out of the supported ones ({@code null} if no initial
     *                                       resource)
     * @throws UnsupportedOperationException if no match found
     */
    static IoResource<?> forResource(Object resource) {
        if (resource == null) {
            return null;
        } else if (resource instanceof Path) {
            return new PathResource((Path) resource);
        } else if (resource instanceof URL) {
            return new URLResource((URL) resource);
        } else if (resource instanceof URI) {
            return new URIResource((URI) resource);
        } else {
            throw new UnsupportedOperationException(
                    "Unsupported resource type " + resource.getClass().getSimpleName() + ": " + resource);
        }
    }
}
