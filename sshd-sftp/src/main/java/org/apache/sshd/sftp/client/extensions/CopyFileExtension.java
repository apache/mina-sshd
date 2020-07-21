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

package org.apache.sshd.sftp.client.extensions;

import java.io.IOException;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://tools.ietf.org/html/draft-ietf-secsh-filexfer-extensions-00#section-6">copy-file
 *         extension</A>
 */
public interface CopyFileExtension extends SftpClientExtension {
    /**
     * @param  src                  The (<U>remote</U>) file source path
     * @param  dst                  The (<U>remote</U>) file destination path
     * @param  overwriteDestination If {@code true} then OK to override destination if exists
     * @throws IOException          If failed to execute the command or extension not supported
     */
    void copyFile(String src, String dst, boolean overwriteDestination) throws IOException;
}
