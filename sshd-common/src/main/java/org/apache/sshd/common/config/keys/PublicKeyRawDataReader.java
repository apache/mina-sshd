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

package org.apache.sshd.common.config.keys;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.resource.IoResource;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.util.io.resource.URLResource;

/**
 * @param  <PUB> The generic {@link PublicKey} type
 * @author       <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PublicKeyRawDataReader<PUB extends PublicKey> {
    default PUB readPublicKey(SessionContext session, Path path, OpenOption... options)
            throws IOException, GeneralSecurityException {
        return readPublicKey(session, path, StandardCharsets.UTF_8, options);
    }

    default PUB readPublicKey(
            SessionContext session, Path path, Charset cs, OpenOption... options)
            throws IOException, GeneralSecurityException {
        return readPublicKey(session, new PathResource(path, options), cs);
    }

    default PUB readPublicKey(SessionContext session, URL url)
            throws IOException, GeneralSecurityException {
        return readPublicKey(session, url, StandardCharsets.UTF_8);
    }

    default PUB readPublicKey(SessionContext session, URL url, Charset cs)
            throws IOException, GeneralSecurityException {
        return readPublicKey(session, new URLResource(url), cs);
    }

    default PUB readPublicKey(SessionContext session, IoResource<?> resource)
            throws IOException, GeneralSecurityException {
        return readPublicKey(session, resource, StandardCharsets.UTF_8);
    }

    default PUB readPublicKey(
            SessionContext session, IoResource<?> resource, Charset cs)
            throws IOException, GeneralSecurityException {
        try (InputStream stream = Objects.requireNonNull(resource, "No resource data").openInputStream()) {
            return readPublicKey(session, resource, stream, cs);
        }
    }

    default PUB readPublicKey(
            SessionContext session, NamedResource resourceKey, InputStream stream)
            throws IOException, GeneralSecurityException {
        return readPublicKey(session, resourceKey, stream, StandardCharsets.UTF_8);
    }

    default PUB readPublicKey(
            SessionContext session, NamedResource resourceKey, InputStream stream, Charset cs)
            throws IOException, GeneralSecurityException {
        try (Reader reader = new InputStreamReader(
                Objects.requireNonNull(stream, "No stream instance"), Objects.requireNonNull(cs, "No charset"))) {
            return readPublicKey(session, resourceKey, reader);
        }
    }

    default PUB readPublicKey(
            SessionContext session, NamedResource resourceKey, Reader rdr)
            throws IOException, GeneralSecurityException {
        try (BufferedReader br
                = new BufferedReader(Objects.requireNonNull(rdr, "No reader instance"), IoUtils.DEFAULT_COPY_SIZE)) {
            return readPublicKey(session, resourceKey, br);
        }
    }

    default PUB readPublicKey(
            SessionContext session, NamedResource resourceKey, BufferedReader rdr)
            throws IOException, GeneralSecurityException {
        List<String> lines = IoUtils.readAllLines(rdr);
        try {
            return readPublicKey(session, resourceKey, lines);
        } finally {
            lines.clear(); // clean up sensitive data a.s.a.p.
        }
    }

    PUB readPublicKey(SessionContext session, NamedResource resourceKey, List<String> lines)
            throws IOException, GeneralSecurityException;
}
