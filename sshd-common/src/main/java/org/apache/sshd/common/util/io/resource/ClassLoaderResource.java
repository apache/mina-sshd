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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;

import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.threads.ThreadUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClassLoaderResource extends AbstractIoResource<ClassLoader> {
    private final String resourceName;

    public ClassLoaderResource(ClassLoader loader, String resourceName) {
        super(ClassLoader.class, (loader == null) ? ThreadUtils.resolveDefaultClassLoader(ClassLoaderResource.class) : loader);
        this.resourceName = ValidateUtils.checkNotNullAndNotEmpty(resourceName, "No resource name provided");
    }

    public ClassLoader getResourceLoader() {
        return getResourceValue();
    }

    @Override
    public String getName() {
        return resourceName;
    }

    @Override
    public InputStream openInputStream() throws IOException {
        String name = getName();
        ClassLoader cl = getResourceLoader();
        if (cl == null) {
            throw new StreamCorruptedException("No resource loader for " + name);
        }

        InputStream input = cl.getResourceAsStream(name);
        if (input == null) {
            throw new FileNotFoundException("Cannot find resource " + name);
        }

        return input;
    }
}
