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
package org.apache.sshd.common.kex;

import java.util.Objects;

import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.digest.DigestFactory;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.security.KEM;

/**
 * A "fake" DH that serves only as a transport object for a {@link KeyEncapsulationMethod} to implement pure PQ key
 * exchange in DHGClient and DHGServer.
 */
public class KEMOnlyDH extends AbstractDH {

    protected final KEM kem;

    protected final DigestFactory digest;

    public KEMOnlyDH(KEM kem, DigestFactory factory) {
        this.kem = Objects.requireNonNull(kem, "A KEM is required");
        this.digest = Objects.requireNonNull(factory, "A DigestFactory is required");
    }

    @Override
    public KEM getKeyEncapsulation() {
        return kem;
    }

    @Override
    public Digest getHash() throws Exception {
        return digest.create();
    }

    @Override
    public void setF(byte[] f) {
        // Nothing
    }

    @Override
    public byte[] getE() throws Exception {
        throw new UnsupportedOperationException("KEM key exchange has no E; in DHGClient e = kemClient.getPublicKey()");
    }

    @Override
    protected byte[] calculateE() throws Exception {
        return null;
    }

    @Override
    protected byte[] calculateK() throws Exception {
        return null;
    }

    @Override
    public void putE(Buffer buffer, byte[] e) {
        // RFC 10042: plain KEM public key is just a byte sequence
        buffer.putBytes(e);
    }

    @Override
    public void putF(Buffer buffer, byte[] f) {
        // RFC 10042: KEM server data is just a byte sequence
        buffer.putBytes(f);
    }

}
