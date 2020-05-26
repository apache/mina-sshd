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
package org.apache.sshd.common.random;

import org.apache.sshd.common.NamedResource;

/**
 * A pseudo random number generator.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Random extends NamedResource {
    /**
     * Fill the buffer with random values
     *
     * @param bytes The bytes to fill
     * @see         #fill(byte[], int, int)
     */
    default void fill(byte[] bytes) {
        fill(bytes, 0, bytes.length);
    }

    /**
     * Fill part of bytes with random values.
     *
     * @param bytes byte array to be filled.
     * @param start index to start filling at.
     * @param len   length of segment to fill.
     */
    void fill(byte[] bytes, int start, int len);

    /**
     * Returns a pseudo-random uniformly distributed {@code int} in the half-open range [0, n).
     *
     * @param  n The range upper limit
     * @return   The randomly selected value in the range
     */
    int random(int n);
}
