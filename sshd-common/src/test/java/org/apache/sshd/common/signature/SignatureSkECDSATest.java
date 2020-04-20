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

import java.security.PublicKey;
import java.util.Base64;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class SignatureSkECDSATest extends JUnitTestSupport {

    @SuppressWarnings("checkstyle:linelength")
    private static final String AUTHORIZED_KEY_ENTRY
            = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBPxnZ6t8ROtXWc3d1mfyz7TRf7qvwefl0cNYSP7G5ePyBeFLka/YeMAc96UEvtn0JIVqrcVDOeLCCr9CcMLAYkUAAAAEc3NoOg==";
    @SuppressWarnings("checkstyle:linelength")
    private static final String MSG1
            = "AAAAIKUkyXDJeM7SrL7YAjI19MXcnGMzABrtyZcMPmngO63gMgAAAAZpaGFrZW4AAAAOc3NoLWNvbm5lY3Rpb24AAAAJcHVibGlja2V5AQAAACJzay1lY2RzYS1zaGEyLW5pc3RwMjU2QG9wZW5zc2guY29tAAAAfwAAACJzay1lY2RzYS1zaGEyLW5pc3RwMjU2QG9wZW5zc2guY29tAAAACG5pc3RwMjU2AAAAQQT8Z2erfETrV1nN3dZn8s+00X+6r8Hn5dHDWEj+xuXj8gXhS5Gv2HjAHPelBL7Z9CSFaq3FQzniwgq/QnDCwGJFAAAABHNzaDo=";
    @SuppressWarnings("checkstyle:linelength")
    private static final String MSG2
            = "AAAAID7kQ1C7gjPZxbodpPXMX4V0MdXBLZX7ruadV05Bad+QMgAAAAZpaGFrZW4AAAAOc3NoLWNvbm5lY3Rpb24AAAAJcHVibGlja2V5AQAAACJzay1lY2RzYS1zaGEyLW5pc3RwMjU2QG9wZW5zc2guY29tAAAAfwAAACJzay1lY2RzYS1zaGEyLW5pc3RwMjU2QG9wZW5zc2guY29tAAAACG5pc3RwMjU2AAAAQQT8Z2erfETrV1nN3dZn8s+00X+6r8Hn5dHDWEj+xuXj8gXhS5Gv2HjAHPelBL7Z9CSFaq3FQzniwgq/QnDCwGJFAAAABHNzaDo=";
    @SuppressWarnings("checkstyle:linelength")
    private static final String SIG_FOR_MSG1_WITH_TOUCH
            = "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAABIAAAAIAfLMrNrJkM2ol83FlDWQ6BYnKUG4U+WfrNL0zoMNm9UAAAAIDd3dMT1Xl02N7wxxlMKZtPyI3GXkGPVyF1n7X00RxtSAQAABBM=";
    @SuppressWarnings("checkstyle:linelength")
    private static final String SIG_FOR_MSG2_WITH_NO_TOUCH
            = "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAABJAAAAIFaWRnqMCe5haZ99AibwyYhi0ui2Uqn2PbWEPOX2afCIAAAAIQDLE7tAhkuazXL+vnU9KXCvleRAbiCoU2Qu4kHfzGbAwQAAAAQp";

    private static final Base64.Decoder B64_DECODER = Base64.getDecoder();

    public SignatureSkECDSATest() {
        super();
    }

    @Test
    public void testValidSignatureWithTouch() throws Exception {
        testSignature(AUTHORIZED_KEY_ENTRY, MSG1, SIG_FOR_MSG1_WITH_TOUCH, true);
    }

    @Test
    public void testValidSignatureWithNoTouch() throws Exception {
        testSignature("no-touch-required " + AUTHORIZED_KEY_ENTRY, MSG2, SIG_FOR_MSG2_WITH_NO_TOUCH, true);
    }

    @Test
    public void testValidSignatureWithMissingTouch() throws Exception {
        testSignature(AUTHORIZED_KEY_ENTRY, MSG2, SIG_FOR_MSG2_WITH_NO_TOUCH, false);
    }

    @Test
    public void testInvalidSignatureWithTouch() throws Exception {
        testSignature(AUTHORIZED_KEY_ENTRY, MSG2, SIG_FOR_MSG1_WITH_TOUCH, false);
    }

    private void testSignature(String authorizedKeyEntry, String msgB64, String sigB64, boolean expected) throws Exception {
        AuthorizedKeyEntry authKey = AuthorizedKeyEntry.parseAuthorizedKeyEntry(authorizedKeyEntry);
        PublicKey publicKey = authKey.resolvePublicKey(null, null);
        byte[] msg = B64_DECODER.decode(msgB64);
        byte[] sig = B64_DECODER.decode(sigB64);
        SignatureSkECDSA verifier = new SignatureSkECDSA();
        verifier.initVerifier(null, publicKey);
        verifier.update(null, msg);
        assertEquals(expected, verifier.verify(null, sig));
    }
}
