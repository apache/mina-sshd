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
import java.util.List;

import org.apache.sshd.common.util.buffer.Buffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see <A HREF="https://tools.ietf.org/html/rfc8308#section-3.1">RFC-8308 - section 3.1</A>
 */
public class ServerSignatureAlgorithms extends AbstractKexExtensionParser<List<String>> {
    public static final String NAME = "server-sig-algs";

    public static final ServerSignatureAlgorithms INSTANCE = new ServerSignatureAlgorithms();

    public ServerSignatureAlgorithms() {
        super(NAME);
    }

    @Override
    public List<String> parseExtension(Buffer buffer) throws IOException {
        return buffer.getNameList();
    }

    @Override
    protected void encode(List<String> names, Buffer buffer) throws IOException {
        buffer.putNameList(names);
    }
}
