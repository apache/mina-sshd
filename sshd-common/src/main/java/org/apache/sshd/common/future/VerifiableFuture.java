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

package org.apache.sshd.common.future;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Represents an asynchronous operation whose successful result can be verified somehow. The contract guarantees that if
 * the {@code verifyXXX} method returns without an exception then the operation was completed <U>successfully</U>
 *
 * @param  <T> Type of verification result
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface VerifiableFuture<T> {
    /**
     * Wait {@link Long#MAX_VALUE} msec. and verify that the operation was successful
     *
     * @return             The (same) future instance
     * @throws IOException If failed to verify successfully on time
     * @see                #verify(long)
     */
    default T verify() throws IOException {
        return verify(Long.MAX_VALUE);
    }

    /**
     * Wait and verify that the operation was successful
     *
     * @param  timeout     The number of time units to wait
     * @param  unit        The wait {@link TimeUnit}
     * @return             The (same) future instance
     * @throws IOException If failed to verify successfully on time
     * @see                #verify(long)
     */
    default T verify(long timeout, TimeUnit unit) throws IOException {
        return verify(unit.toMillis(timeout));
    }

    /**
     * Wait and verify that the operation was successful
     *
     * @param  timeout     The maximum duration to wait, <code>null</code> to wait forever
     * @return             The (same) future instance
     * @throws IOException If failed to verify successfully on time
     * @see                #verify(long)
     */
    default T verify(Duration timeout) throws IOException {
        return timeout != null ? verify(timeout.toMillis()) : verify();
    }

    /**
     * Wait and verify that the operation was successful
     *
     * @param  timeoutMillis Wait timeout in milliseconds
     * @return               The (same) future instance
     * @throws IOException   If failed to verify successfully on time
     */
    T verify(long timeoutMillis) throws IOException;
}
