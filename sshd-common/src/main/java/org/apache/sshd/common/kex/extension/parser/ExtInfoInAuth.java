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
package org.apache.sshd.common.kex.extension.parser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.sshd.common.util.buffer.Buffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF=
 *         "https://github.com/openssh/openssh-portable/blob/V_9_8/PROTOCOL#L167-L184">ext-info-in-auth@openssh.com</A>
 */
public class ExtInfoInAuth extends AbstractKexExtensionParser<String> {

    public static final String NAME = "ext-info-in-auth@openssh.com";

    public static final ExtInfoInAuth INSTANCE = new ExtInfoInAuth();

    public ExtInfoInAuth() {
        super(NAME);
    }

    @Override
    protected void encode(String value, Buffer buffer) throws IOException {
        buffer.putString(value);
    }

    @Override
    public String parseExtension(byte[] data, int off, int len) throws IOException {
        return (len <= 0) ? "" : new String(data, off, len, StandardCharsets.UTF_8);
    }

    @Override
    public String parseExtension(Buffer buffer) throws IOException {
        return parseExtension(buffer.array(), buffer.rpos(), buffer.available());
    }
}
