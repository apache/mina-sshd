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
package org.apache.sshd.sftp.client.fs.impl;

/**
 * Internal utilities for SFTP file systems.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class SftpUtils {

    /**
     * For internal uses, this can be set to Boolean.TRUE to indicate that a SftpDirectoryStream created shall report
     * the "." and ".." entries (which Java normally doesn't do, but which we do get from the SFTP server). The stream,
     * if it recognizes this, will set the value to {@code null}, so code using this can check after having created the
     * stream whether it will return these entries (value is {@code null}). Intended usage:
     *
     * <pre>
     * SftpUtils.DIRECTORY_WITH_DOTS.set(Boolean.TRUE);
     * DirectoryStream&lt;Path&gt; dir = Files.newDirectoryStream(somePath);
     * boolean withDots = SftpUtils.DIRECTORY_WITH_DOTS.get() == null;
     * SftpUtil.DIRECTORY_WITH_DOTS.remove();
     * </pre>
     */
    public static final ThreadLocal<Boolean> DIRECTORY_WITH_DOTS = new ThreadLocal<>();

    private SftpUtils() {
        throw new IllegalStateException("No instantiation");
    }

}
