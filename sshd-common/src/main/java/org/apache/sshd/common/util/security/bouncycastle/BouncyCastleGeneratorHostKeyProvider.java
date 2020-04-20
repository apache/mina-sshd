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
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.keyprovider.AbstractGeneratorHostKeyProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BouncyCastleGeneratorHostKeyProvider extends AbstractGeneratorHostKeyProvider {
    public BouncyCastleGeneratorHostKeyProvider(Path path) {
        setPath(path);
    }

    @Override
    protected void doWriteKeyPair(NamedResource resourceKey, KeyPair kp, OutputStream outputStream)
            throws IOException, GeneralSecurityException {
        writePEMKeyPair(kp, outputStream);
    }

    public static void writePEMKeyPair(KeyPair kp, Path targetPath) throws IOException {
        writePEMKeyPair(kp, targetPath, IoUtils.EMPTY_OPEN_OPTIONS);
    }

    public static void writePEMKeyPair(
            KeyPair kp, Path targetPath, OpenOption... options)
            throws IOException {
        try (OutputStream os = Files.newOutputStream(targetPath, options)) {
            writePEMKeyPair(kp, os);
        }
    }

    public static void writePEMKeyPair(KeyPair kp, OutputStream outputStream) throws IOException {
        try (JcaPEMWriter w = new JcaPEMWriter(
                new OutputStreamWriter(outputStream, StandardCharsets.UTF_8))) {
            w.writeObject(kp);
            w.flush();
        }
    }
}
