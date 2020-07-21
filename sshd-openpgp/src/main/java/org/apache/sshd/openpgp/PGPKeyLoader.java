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

package org.apache.sshd.openpgp;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.resource.IoResource;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.util.io.resource.URLResource;
import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.Key;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PGPKeyLoader {
    default Key loadPGPKey(
            SessionContext session, URL url, FilePasswordProvider passwordProvider)
            throws IOException, GeneralSecurityException, PGPException {
        return loadPGPKey(session, new URLResource(url), passwordProvider);
    }

    default Key loadPGPKey(
            SessionContext session, Path path, FilePasswordProvider passwordProvider, OpenOption... options)
            throws IOException, GeneralSecurityException, PGPException {
        return loadPGPKey(session, new PathResource(path, options), passwordProvider);
    }

    default Key loadPGPKey(
            SessionContext session, IoResource<?> resourceKey, FilePasswordProvider passwordProvider)
            throws IOException, GeneralSecurityException, PGPException {
        try (InputStream input = resourceKey.openInputStream()) {
            return loadPGPKey(session, resourceKey, passwordProvider, input);
        }
    }

    default Key loadPGPKey(
            SessionContext session, NamedResource resourceKey, FilePasswordProvider passwordProvider, InputStream input)
            throws IOException, GeneralSecurityException, PGPException {
        return loadPGPKey(input, (passwordProvider == null) ? null : passwordProvider.getPassword(session, resourceKey, 0));
    }

    static Key loadPGPKey(InputStream input, String password) throws IOException, PGPException {
        boolean withPassword = GenericUtils.isNotEmpty(password);
        Key key = withPassword ? new Key(input, password) : new Key(input);
        if (!withPassword) {
            key.setNoPassphrase(true);
        }
        return key;
    }
}
