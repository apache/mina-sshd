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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HostBoundPubkeyAuthentication extends AbstractKexExtensionParser<Integer> {

    public static final String NAME = "publickey-hostbound@openssh.com";

    public static final String AUTH_NAME = "publickey-hostbound-v00@openssh.com";

    public static final HostBoundPubkeyAuthentication INSTANCE = new HostBoundPubkeyAuthentication();

    private static final Logger LOG = LoggerFactory.getLogger(HostBoundPubkeyAuthentication.class);

    public HostBoundPubkeyAuthentication() {
        super(NAME);
    }

    @Override
    public Integer parseExtension(Buffer buffer) throws IOException {
        return parseExtension(buffer.array(), buffer.rpos(), buffer.available());
    }

    @Override
    public Integer parseExtension(byte[] data, int off, int len) throws IOException {
        if (len <= 0) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Inconsistent KEX extension {} received; no data (len={})", NAME, len);
            }
            return null;
        }
        String value = new String(data, off, len, StandardCharsets.UTF_8);
        try {
            Integer result = Integer.valueOf(Integer.parseUnsignedInt(value));
            LOG.info("Server announced support for {} version {}", NAME, result);
            return result;
        } catch (NumberFormatException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Cannot parse KEX extension {} version {}", NAME, value);
            }
        }
        return null;
    }

    @Override
    protected void encode(Integer version, Buffer buffer) throws IOException {
        buffer.putString(version.toString());
    }
}
