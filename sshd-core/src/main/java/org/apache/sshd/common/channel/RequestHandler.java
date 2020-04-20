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
package org.apache.sshd.common.channel;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * A global request handler.
 *
 * @param  <T> Request type
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface RequestHandler<T> {

    enum Result {
        Unsupported,
        Replied,
        ReplySuccess,
        ReplyFailure;

        public static final Set<Result> VALUES = Collections.unmodifiableSet(EnumSet.allOf(Result.class));

        /**
         * @param  name The result name - ignored if {@code null}/empty
         * @return      The matching {@link Result} value (case <U>insensitive</U>) or {@code null} if no match found
         */
        public static Result fromName(String name) {
            if (GenericUtils.isEmpty(name)) {
                return null;
            }

            for (Result r : VALUES) {
                if (name.equalsIgnoreCase(r.name())) {
                    return r;
                }
            }

            return null;
        }
    }

    /**
     * Process an SSH request. If an exception is thrown, the ConnectionService will send a failure message if needed
     * and the request will be considered handled.
     * 
     * @param  t         The input parameter
     * @param  request   The request string
     * @param  wantReply Whether a reply is requested
     * @param  buffer    The {@link Buffer} with request specific data
     * @return           The {@link Result}
     * @throws Exception If failed to handle the request - <B>Note:</B> in order to signal an unsupported request the
     *                   {@link Result#Unsupported} value should be returned
     */
    Result process(T t, String request, boolean wantReply, Buffer buffer) throws Exception;
}
