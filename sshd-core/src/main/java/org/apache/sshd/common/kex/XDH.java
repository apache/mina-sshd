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

import java.security.KeyPair;
import java.util.Objects;

import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Provides Diffie-Hellman SSH key exchange algorithms for the Montgomery curves specified in RFC 8731.
 *
 * @see <a href="https://www.rfc-editor.org/info/rfc8731">RFC 8731</a>
 */
public class XDH extends AbstractDH {

    protected MontgomeryCurve curve;
    protected byte[] f;

    public XDH(MontgomeryCurve curve) throws Exception {
        this.curve = Objects.requireNonNull(curve, "No MontgomeryCurve provided");
        myKeyAgree = curve.createKeyAgreement();
    }

    @Override
    protected byte[] calculateE() throws Exception {
        KeyPair keyPair = curve.generateKeyPair();
        myKeyAgree.init(keyPair.getPrivate());
        return curve.encode(keyPair.getPublic());
    }

    @Override
    public void setF(byte[] f) {
        this.f = Objects.requireNonNull(f, "No 'f' value provided");
    }

    @Override
    public void putE(Buffer buffer, byte[] e) {
        // RFC 5656, section 4: Q_C and Q_S, which take the place of e and f, are written as "strings", i.e., byte
        // arrays.
        // RFC 8731, section 3: Public ephemeral keys are encoded for transmission as standard SSH strings. (Q_C and Q_S
        // are the client's and server's ephemeral public keys.)
        buffer.putBytes(e);
    }

    @Override
    public void putF(Buffer buffer, byte[] f) {
        // RFC 5656, section 4: Q_C and Q_S, which take the place of e and f, are written as "strings", i.e., byte
        // arrays.
        // RFC 8731, section 3: Public ephemeral keys are encoded for transmission as standard SSH strings. (Q_C and Q_S
        // are the client's and server's ephemeral public keys.)
        buffer.putBytes(f);
    }

    @Override
    protected byte[] calculateK() throws Exception {
        Objects.requireNonNull(f, "Missing 'f' value");
        myKeyAgree.doPhase(curve.decode(f), true);
        return stripLeadingZeroes(myKeyAgree.generateSecret());
    }

    @Override
    public Digest getHash() throws Exception {
        return curve.createDigest();
    }
}
