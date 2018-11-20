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
package org.apache.sshd.server.keyprovider;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.session.SessionContext;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SimpleGeneratorHostKeyProvider extends AbstractGeneratorHostKeyProvider {
    public SimpleGeneratorHostKeyProvider() {
        super();
    }

    public SimpleGeneratorHostKeyProvider(Path path) {
        setPath(path);
    }

    @Override
    protected Iterable<KeyPair> doReadKeyPairs(SessionContext session, NamedResource resourceKey, InputStream inputStream)
            throws IOException, GeneralSecurityException {
        KeyPair kp;
        try (ObjectInputStream r = new ObjectInputStream(inputStream)) {
            try {
                kp = (KeyPair) r.readObject();
            } catch (ClassNotFoundException e) {
                throw new InvalidKeySpecException("Missing classes: " + e.getMessage(), e);
            }
        }

        return Collections.singletonList(kp);
    }

    @Override
    protected void doWriteKeyPair(NamedResource resourceKey, KeyPair kp, OutputStream outputStream)
            throws IOException, GeneralSecurityException {
        try (ObjectOutputStream w = new ObjectOutputStream(outputStream)) {
            w.writeObject(kp);
        }
    }
}
