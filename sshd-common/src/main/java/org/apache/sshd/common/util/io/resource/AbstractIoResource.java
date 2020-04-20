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

import java.util.Objects;

/**
 * TODO Add javadoc
 *
 * @param  <T> Type of resource
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractIoResource<T> implements IoResource<T> {
    private final Class<T> resourceType;
    private final T resourceValue;

    protected AbstractIoResource(Class<T> resourceType, T resourceValue) {
        this.resourceType = Objects.requireNonNull(resourceType, "No resource type specified");
        this.resourceValue = Objects.requireNonNull(resourceValue, "No resource value provided");
    }

    @Override
    public Class<T> getResourceType() {
        return resourceType;
    }

    @Override
    public T getResourceValue() {
        return resourceValue;
    }

    @Override
    public String getName() {
        return Objects.toString(getResourceValue(), null);
    }

    @Override
    public String toString() {
        return getName();
    }
}
