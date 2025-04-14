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

import java.io.Closeable;
import java.io.IOException;

/**
 * An {@code AuthenticationHandler} encapsulates a possibly multi-step authentication protocol. Intended usage:
 *
 * <pre>
 * setParams(something);
 * start();
 * sendToken(getToken());
 * while (!isDone()) {
 *     setParams(receiveMessageAndExtractParams());
 *     process();
 *     Object t = getToken();
 *     if (t != null) {
 *         sendToken(t);
 *     }
 * }
 * </pre>
 *
 * An {@code AuthenticationHandler} may be stateful and therefore is a {@link Closeable}.
 *
 * @param <P> defining the parameter type for {@link #setParams(Object)}
 * @param <T> defining the token type for {@link #getToken()}
 */
public interface AuthenticationHandler<P, T> extends Closeable {

    /**
     * Produces the initial authentication token that can be then retrieved via {@link #getToken()}.
     *
     * @throws Exception if an error occurs
     */
    void start() throws IOException;

    /**
     * Produces the next authentication token, if any.
     *
     * @throws Exception if an error occurs
     */
    void process() throws Exception;

    /**
     * Sets the parameters for the next token generation via {@link #start()} or {@link #process()}.
     *
     * @param input to set, may be {@code null}
     */
    void setParams(P input);

    /**
     * Retrieves the last token generated.
     *
     * @return           the token, or {@code null} if there is none
     * @throws Exception if an error occurs
     */
    T getToken() throws IOException;

    /**
     * Tells whether is authentication mechanism is done (successfully or unsuccessfully).
     *
     * @return whether this authentication is done
     */
    boolean isDone();

    @Override
    void close();
}
