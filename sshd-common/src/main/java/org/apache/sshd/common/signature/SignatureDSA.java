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
package org.apache.sshd.common.signature;

import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.security.SignatureException;
import java.util.Map;

import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.io.der.DERParser;
import org.apache.sshd.common.util.io.der.DERWriter;

/**
 * DSA <code>Signature</code>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://tools.ietf.org/html/rfc4253#section-6.6">RFC4253 section 6.6</A>
 */
public class SignatureDSA extends AbstractSignature {
    public static final String DEFAULT_ALGORITHM = "SHA1withDSA";

    public static final int DSA_SIGNATURE_LENGTH = 40;
    // result must be 40 bytes, but length of r and s may not exceed 20 bytes
    public static final int MAX_SIGNATURE_VALUE_LENGTH = DSA_SIGNATURE_LENGTH / 2;

    public SignatureDSA() {
        this(DEFAULT_ALGORITHM);
    }

    protected SignatureDSA(String algorithm) {
        super(algorithm);
    }

    @Override
    public byte[] sign(SessionContext session) throws Exception {
        byte[] sig = super.sign(session);

        try (DERParser parser = new DERParser(sig)) {
            int type = parser.read();
            if (type != 0x30) {
                throw new StreamCorruptedException(
                        "Invalid signature format - not a DER SEQUENCE: 0x" + Integer.toHexString(type));
            }

            // length of remaining encoding of the 2 integers
            int remainLen = parser.readLength();
            /*
             * There are supposed to be 2 INTEGERs, each encoded with:
             *
             * - one byte representing the fact that it is an INTEGER - one byte of the integer encoding length - at
             * least one byte of integer data (zero length is not an option)
             */
            if (remainLen < (2 * 3)) {
                throw new StreamCorruptedException(
                        "Invalid signature format - not enough encoded data length: " + remainLen);
            }

            BigInteger r = parser.readBigInteger();
            BigInteger s = parser.readBigInteger();

            byte[] result = new byte[DSA_SIGNATURE_LENGTH];
            putBigInteger(r, result, 0);
            putBigInteger(s, result, MAX_SIGNATURE_VALUE_LENGTH);
            return result;
        }
    }

    public static void putBigInteger(BigInteger value, byte[] result, int offset) {
        byte[] data = value.toByteArray();
        boolean maxExceeded = data.length > MAX_SIGNATURE_VALUE_LENGTH;
        int dstOffset = maxExceeded ? 0 : (MAX_SIGNATURE_VALUE_LENGTH - data.length);
        System.arraycopy(data, maxExceeded ? 1 : 0,
                result, offset + dstOffset,
                Math.min(MAX_SIGNATURE_VALUE_LENGTH, data.length));
    }

    @Override
    public boolean verify(SessionContext session, byte[] sig) throws Exception {
        int sigLen = NumberUtils.length(sig);
        byte[] data = sig;

        if (sigLen != DSA_SIGNATURE_LENGTH) {
            // probably some encoded data
            Map.Entry<String, byte[]> encoding = extractEncodedSignature(sig, k -> KeyPairProvider.SSH_DSS.equalsIgnoreCase(k));
            if (encoding != null) {
                String keyType = encoding.getKey();
                ValidateUtils.checkTrue(
                        KeyPairProvider.SSH_DSS.equals(keyType), "Mismatched key type: %s", keyType);
                data = encoding.getValue();
                sigLen = NumberUtils.length(data);
            }
        }

        if (sigLen != DSA_SIGNATURE_LENGTH) {
            throw new SignatureException(
                    "Bad signature length (" + sigLen + " instead of " + DSA_SIGNATURE_LENGTH + ")"
                                         + " for " + BufferUtils.toHex(':', data));
        }

        byte[] rEncoding;
        try (DERWriter w = new DERWriter(MAX_SIGNATURE_VALUE_LENGTH + 4)) { // in case length > 0x7F
            w.writeBigInteger(data, 0, MAX_SIGNATURE_VALUE_LENGTH);
            rEncoding = w.toByteArray();
        }

        byte[] sEncoding;
        try (DERWriter w = new DERWriter(MAX_SIGNATURE_VALUE_LENGTH + 4)) { // in case length > 0x7F
            w.writeBigInteger(data, MAX_SIGNATURE_VALUE_LENGTH, MAX_SIGNATURE_VALUE_LENGTH);
            sEncoding = w.toByteArray();
        }

        int length = rEncoding.length + sEncoding.length;
        byte[] encoded;
        try (DERWriter w = new DERWriter(1 + length + 4)) { // in case length > 0x7F
            w.write(0x30); // SEQUENCE
            w.writeLength(length);
            w.write(rEncoding);
            w.write(sEncoding);
            encoded = w.toByteArray();
        }

        return doVerify(encoded);
    }
}
