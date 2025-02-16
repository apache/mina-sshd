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
package org.apache.sshd.common.filter;

import java.util.Objects;

/**
 * A base implementation of a {@link Filter}.
 */
public abstract class IoFilter implements Filter {

    private volatile FilterChain chain;

    protected IoFilter() {
        super();
    }

    @Override
    public void init() {
        // Nothing
    }

    @Override
    public void adding(FilterChain chain) {
        // Nothing
    }

    @Override
    public void added(FilterChain chain) {
        this.chain = Objects.requireNonNull(chain);
    }

    @Override
    public void removing() {
        chain = null;
    }

    @Override
    public void removed(FilterChain chain) {
        // Nothing
    }

    @Override
    public FilterChain owner() {
        return chain;
    }

    protected FilterChain active() {
        FilterChain myChain = chain;
        if (myChain == null || myChain.owner() == null) {
            throw new IllegalStateException();
        }
        return myChain;
    }

}
