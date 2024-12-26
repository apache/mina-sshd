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

package org.apache.sshd.common.util.security.eddsa.generic;

import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.loader.pem.AbstractPEMResourceKeyPairParser;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.der.ASN1Object;
import org.apache.sshd.common.util.io.der.ASN1Type;
import org.apache.sshd.common.util.io.der.DERParser;
import org.apache.sshd.common.util.io.input.NoCloseInputStream;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class GenericEd25519PEMResourceKeyParser extends AbstractPEMResourceKeyPairParser {

    // From an early draft of RFC 8410 (https://datatracker.ietf.org/doc/html/draft-ietf-curdle-pkix-eddsa-00).
    // The final RFC 8410 dropped the "EDDSA" and moved to PKCS#8 using just "BEGIN PRIVATE KEY".
    public static final String BEGIN_MARKER = "BEGIN EDDSA PRIVATE KEY";

    // Some (older) OpenSSL versions used this if "traditional" (RFC 1421) PEM format was chosen:
    public static final String BEGIN_ED25519_MARKER = "BEGIN ED25519 PRIVATE KEY";

    public static final List<String> BEGINNERS = GenericUtils.unmodifiableList(BEGIN_MARKER, BEGIN_ED25519_MARKER);

    public static final String END_MARKER = "END EDDSA PRIVATE KEY";
    public static final String END_ED25519_MARKER = "END ED25519 PRIVATE KEY";
    public static final List<String> ENDERS = GenericUtils.unmodifiableList(END_MARKER, END_ED25519_MARKER);

    public static final String ED25519_OID = EdDSASupport.ED25519_OID;

    public static final GenericEd25519PEMResourceKeyParser INSTANCE = new GenericEd25519PEMResourceKeyParser();

    public GenericEd25519PEMResourceKeyParser() {
        super(SecurityUtils.EDDSA, ED25519_OID, BEGINNERS, ENDERS);
    }

    @Override
    public Collection<KeyPair> extractKeyPairs(
            SessionContext session, NamedResource resourceKey, String beginMarker,
            String endMarker, FilePasswordProvider passwordProvider,
            InputStream stream, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        KeyPair kp = parseEd25519KeyPair(stream, false);
        return Collections.singletonList(kp);
    }

    public static KeyPair parseEd25519KeyPair(
            InputStream inputStream, boolean okToClose)
            throws IOException, GeneralSecurityException {
        try (DERParser parser = new DERParser(NoCloseInputStream.resolveInputStream(inputStream, okToClose))) {
            return parseEd25519KeyPair(parser);
        }
    }

    /*
     * See https://tools.ietf.org/html/rfc8410#section-7
     *
     * SEQUENCE {
     *      INTEGER 0x00 (0 decimal)
     *      SEQUENCE {
     *          OBJECTIDENTIFIER 1.3.101.112
     *      }
     *      OCTETSTRING keyData
     * }
     *
     * NOTE: there is another variant that also has some extra parameters
     * but it has the same "prefix" structure so we don't care
     */
    public static KeyPair parseEd25519KeyPair(DERParser parser) throws IOException, GeneralSecurityException {
        ASN1Object obj = parser.readObject();
        if (obj == null) {
            throw new StreamCorruptedException("Missing version value");
        }

        BigInteger version = obj.asInteger();
        if (!BigInteger.ZERO.equals(version)) {
            throw new StreamCorruptedException("Invalid version: " + version);
        }

        obj = parser.readObject();
        if (obj == null) {
            throw new StreamCorruptedException("Missing OID container");
        }

        ASN1Type objType = obj.getObjType();
        if (objType != ASN1Type.SEQUENCE) {
            throw new StreamCorruptedException("Unexpected OID object type: " + objType);
        }

        List<Integer> curveOid;
        try (DERParser oidParser = obj.createParser()) {
            obj = oidParser.readObject();
            if (obj == null) {
                throw new StreamCorruptedException("Missing OID value");
            }

            curveOid = obj.asOID();
        }

        String oid = GenericUtils.join(curveOid, '.');
        // TODO modify if more curves supported
        if (!ED25519_OID.equals(oid)) {
            throw new StreamCorruptedException("Unsupported curve OID: " + oid);
        }

        obj = parser.readObject();
        if (obj == null) {
            throw new StreamCorruptedException("Missing key data");
        }

        return decodeEd25519KeyPair(obj.getValue());
    }

    public static KeyPair decodeEd25519KeyPair(byte[] keyData) throws IOException, GeneralSecurityException {
        return EdDSASupport.decodeEd25519KeyPair(keyData);
    }

}
