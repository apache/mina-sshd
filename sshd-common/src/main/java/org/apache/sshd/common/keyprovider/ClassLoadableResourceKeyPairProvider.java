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

import java.security.KeyPair;
import java.util.Collection;
import java.util.Collections;

import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.resource.ClassLoaderResource;
import org.apache.sshd.common.util.io.resource.IoResource;
import org.apache.sshd.common.util.threads.ThreadUtils;

/**
 * This provider loads private keys from the specified resources that are accessible via
 * {@link ClassLoader#getResourceAsStream(String)}. If no loader configured via {@link #setResourceLoader(ClassLoader)},
 * then {@link ThreadUtils#resolveDefaultClassLoader(Class)} is used
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClassLoadableResourceKeyPairProvider extends AbstractResourceKeyPairProvider<String> {
    private ClassLoader classLoader;
    private Collection<String> resources;

    public ClassLoadableResourceKeyPairProvider() {
        this(Collections.emptyList());
    }

    public ClassLoadableResourceKeyPairProvider(ClassLoader cl) {
        this(cl, Collections.emptyList());
    }

    public ClassLoadableResourceKeyPairProvider(String res) {
        this(Collections.singletonList(ValidateUtils.checkNotNullAndNotEmpty(res, "No resource specified")));
    }

    public ClassLoadableResourceKeyPairProvider(ClassLoader cl, String res) {
        this(cl, Collections.singletonList(ValidateUtils.checkNotNullAndNotEmpty(res, "No resource specified")));
    }

    public ClassLoadableResourceKeyPairProvider(Collection<String> resources) {
        this.classLoader = ThreadUtils.resolveDefaultClassLoader(getClass());
        this.resources = (resources == null) ? Collections.emptyList() : resources;
    }

    public ClassLoadableResourceKeyPairProvider(ClassLoader cl, Collection<String> resources) {
        this.classLoader = cl;
        this.resources = (resources == null) ? Collections.emptyList() : resources;
    }

    public Collection<String> getResources() {
        return resources;
    }

    public void setResources(Collection<String> resources) {
        this.resources = (resources == null) ? Collections.emptyList() : resources;
    }

    public ClassLoader getResourceLoader() {
        return classLoader;
    }

    public void setResourceLoader(ClassLoader classLoader) {
        this.classLoader = classLoader;
    }

    @Override
    public Iterable<KeyPair> loadKeys(SessionContext session) {
        return loadKeys(session, getResources());
    }

    @Override
    protected IoResource<?> getIoResource(SessionContext session, String resource) {
        return new ClassLoaderResource(resolveClassLoader(), resource);
    }

    protected ClassLoader resolveClassLoader() {
        ClassLoader cl = getResourceLoader();
        if (cl == null) {
            cl = ThreadUtils.resolveDefaultClassLoader(getClass());
        }
        return cl;
    }
}
