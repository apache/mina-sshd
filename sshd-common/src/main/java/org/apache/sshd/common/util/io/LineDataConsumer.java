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

package org.apache.sshd.common.util.io;

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.util.Objects;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface LineDataConsumer {
    /**
     * Ignores anything provided to it
     */
    LineDataConsumer IGNORE = lineData -> {
        // do nothing
    };

    /**
     * Throws {@link StreamCorruptedException} with the invoked line data
     */
    LineDataConsumer FAIL = lineData -> {
        throw new StreamCorruptedException(Objects.toString(lineData));
    };

    void consume(CharSequence lineData) throws IOException;
}
