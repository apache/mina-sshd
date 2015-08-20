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
package org.apache.sshd.common.keyprovider;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.security.KeyPair;
import java.util.Collection;
import java.util.Collections;

import org.apache.sshd.common.util.threads.ThreadUtils;

/**
 * This provider loads private keys from the specified resources that
 * are accessible via {@link ClassLoader#getResourceAsStream(String)}.
 * If no loader configured via {@link #setResourceLoader(ClassLoader)}, then
 * {@link ThreadUtils#resolveDefaultClassLoader(Class)} is used
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractClassLoadableResourceKeyPairProvider extends AbstractResourceKeyPairProvider<String> {
    private ClassLoader classLoader;
    private Collection<String> resources;

    protected AbstractClassLoadableResourceKeyPairProvider() {
        classLoader = ThreadUtils.resolveDefaultClassLoader(getClass());
    }

    public Collection<String> getResources() {
        return resources;
    }

    public void setResources(Collection<String> resources) {
        this.resources = (resources == null) ? Collections.<String>emptyList() : resources;
    }

    public ClassLoader getResourceLoader() {
        return classLoader;
    }

    public void setResourceLoader(ClassLoader classLoader) {
        this.classLoader = classLoader;
    }

    @Override
    public Iterable<KeyPair> loadKeys() {
        return loadKeys(getResources());
    }

    @Override
    protected InputStream openKeyPairResource(String resourceKey, String resource) throws IOException {
        ClassLoader cl = resolveClassLoader();
        if (cl == null) {
            throw new StreamCorruptedException("No resource loader for " + resource);
        }

        InputStream input = cl.getResourceAsStream(resource);
        if (input == null) {
            throw new FileNotFoundException("Cannot find resource " + resource);
        }

        return input;
    }

    protected ClassLoader resolveClassLoader() {
        ClassLoader cl = getResourceLoader();
        if (cl == null) {
            cl = ThreadUtils.resolveDefaultClassLoader(getClass());
        }
        return cl;
    }
}