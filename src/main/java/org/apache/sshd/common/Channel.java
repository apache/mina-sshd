/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common;

import java.io.Closeable;
import java.io.IOException;

import org.apache.sshd.common.util.Buffer;

public interface Channel extends Closeable {

    int getId();

    void handleWindowAdjust(Buffer buffer) throws IOException;

    void handleRequest(Buffer buffer) throws IOException;

    void handleData(Buffer buffer) throws IOException;

    void handleExtendedData(Buffer buffer) throws IOException;

    void handleEof() throws IOException;

    void handleFailure() throws IOException;

}
