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
import java.util.Map;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.der.DERParser;
import org.apache.sshd.common.util.io.der.DERWriter;

/**
 * Signature algorithm for EC keys using ECDSA.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="http://tools.ietf.org/html/rfc3278#section-8.2">RFC3278 section 8.2</A>
 */
public class SignatureECDSA extends AbstractSignature {
    public static class SignatureECDSA256 extends SignatureECDSA {
        public static final String DEFAULT_ALGORITHM = "SHA256withECDSA";

        public SignatureECDSA256() {
            super(DEFAULT_ALGORITHM);
        }
    }

    public static class SignatureECDSA384 extends SignatureECDSA {
        public static final String DEFAULT_ALGORITHM = "SHA384withECDSA";

        public SignatureECDSA384() {
            super(DEFAULT_ALGORITHM);
        }
    }

    public static class SignatureECDSA521 extends SignatureECDSA {
        public static final String DEFAULT_ALGORITHM = "SHA512withECDSA";

        public SignatureECDSA521() {
            super(DEFAULT_ALGORITHM);
        }
    }

    protected SignatureECDSA(String algo) {
        super(algo);
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
            // Write the <r,s> to its own types writer.
            Buffer rsBuf = new ByteArrayBuffer();
            rsBuf.putMPInt(r);
            rsBuf.putMPInt(s);

            return rsBuf.getCompactData();
        }
    }

    @Override
    public boolean verify(SessionContext session, byte[] sig) throws Exception {
        byte[] data = sig;
        Map.Entry<String, byte[]> encoding = extractEncodedSignature(data, ECCurves.KEY_TYPES);
        if (encoding != null) {
            String keyType = encoding.getKey();
            ECCurves curve = ECCurves.fromKeyType(keyType);
            ValidateUtils.checkNotNull(curve, "Unknown curve type: %s", keyType);
            data = encoding.getValue();
        }

        Buffer rsBuf = new ByteArrayBuffer(data);
        byte[] rArray = rsBuf.getMPIntAsBytes();
        byte[] rEncoding;
        try (DERWriter w = new DERWriter(rArray.length + 4)) { // in case length > 0x7F
            w.writeBigInteger(rArray);
            rEncoding = w.toByteArray();
        }

        byte[] sArray = rsBuf.getMPIntAsBytes();
        byte[] sEncoding;
        try (DERWriter w = new DERWriter(sArray.length + 4)) { // in case length > 0x7F
            w.writeBigInteger(sArray);
            sEncoding = w.toByteArray();
        }

        int remaining = rsBuf.available();
        if (remaining != 0) {
            throw new StreamCorruptedException("Signature had padding - remaining=" + remaining);
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
