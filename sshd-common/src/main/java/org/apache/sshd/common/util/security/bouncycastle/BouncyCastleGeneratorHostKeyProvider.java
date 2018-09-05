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
package org.apache.sshd.common.util.security.bouncycastle;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

import org.apache.sshd.server.keyprovider.AbstractGeneratorHostKeyProvider;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BouncyCastleGeneratorHostKeyProvider extends AbstractGeneratorHostKeyProvider {
    public BouncyCastleGeneratorHostKeyProvider(Path path) {
        setPath(path);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void doWriteKeyPair(String resourceKey, KeyPair kp, OutputStream outputStream) throws IOException, GeneralSecurityException {
        try (org.bouncycastle.openssl.PEMWriter w =
                     new org.bouncycastle.openssl.PEMWriter(new OutputStreamWriter(outputStream, StandardCharsets.UTF_8))) {
            w.writeObject(kp);
            w.flush();
        }
    }
}