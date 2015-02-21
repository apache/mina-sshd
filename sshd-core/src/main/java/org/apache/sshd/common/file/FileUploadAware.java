/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.common.file;

import java.io.IOException;

/**
 * Interface that can be implemented by a server-side file's OutputStream to be
 * aware of successful uploads.
 */
public interface FileUploadAware {
    /**
     * Handle a successful upload, called immediately before the stream is
     * closed. This method will not be called if the upload halted, for example
     * due to being aborted, suffering a lost connection or pausing.
     * <p>
     * Note that if the stream throws an exception while being written it is
     * undefined whether this method will be called.
     * @throws IOException
     */
    void handleSuccess() throws IOException;
}
