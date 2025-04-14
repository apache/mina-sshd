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
package org.apache.sshd.client.session.proxy;

import java.net.InetSocketAddress;

/**
 * Abstract base class for {@link AuthenticationHandler}s encapsulating basic common things.
 *
 * @param <P> defining the parameter type for the authentication
 * @param <T> defining the token type for the authentication
 */
public abstract class AbstractAuthenticationHandler<P, T> implements AuthenticationHandler<P, T> {

    /** The {@link InetSocketAddress} of the proxy to connect to. */
    protected InetSocketAddress proxy;

    /** The last set parameters. */
    protected P params;

    /** A flag telling whether this authentication is done. */
    protected boolean done;

    /**
     * Creates a new {@link AbstractAuthenticationHandler} to authenticate with the given {@code proxy}.
     *
     * @param proxy the {@link InetSocketAddress} of the proxy to connect to
     */
    protected AbstractAuthenticationHandler(InetSocketAddress proxy) {
        this.proxy = proxy;
    }

    @Override
    public final void setParams(P input) {
        params = input;
    }

    @Override
    public final boolean isDone() {
        return done;
    }

}
