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
public class SignatureSkED25519Test extends JUnitTestSupport {

    @SuppressWarnings("checkstyle:linelength")
    private static final String AUTHORIZED_KEY_ENTRY
            = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIEjahZEWzksVzyYNa2cC4B3MggcM/3UcCAIgsAnHzdP/AAAABHNzaDo=";
    @SuppressWarnings("checkstyle:linelength")
    private static final String MSG1
            = "AAAAIEHcayiA61I2hzGZ8D7dNDmPEKltvoU3GFLosX1FldmCMgAAAAZpaGFrZW4AAAAOc3NoLWNvbm5lY3Rpb24AAAAJcHVibGlja2V5AQAAABpzay1zc2gtZWQyNTUxOUBvcGVuc3NoLmNvbQAAAEoAAAAac2stc3NoLWVkMjU1MTlAb3BlbnNzaC5jb20AAAAgSNqFkRbOSxXPJg1rZwLgHcyCBwz/dRwIAiCwCcfN0/8AAAAEc3NoOg==";
    @SuppressWarnings("checkstyle:linelength")
    private static final String MSG2
            = "AAAAIIABc6ftGmOciwBGd5/kVu2PX29mjUAZ1E2RirO8VNOzMgAAAAZpaGFrZW4AAAAOc3NoLWNvbm5lY3Rpb24AAAAJcHVibGlja2V5AQAAABpzay1zc2gtZWQyNTUxOUBvcGVuc3NoLmNvbQAAAEoAAAAac2stc3NoLWVkMjU1MTlAb3BlbnNzaC5jb20AAAAgSNqFkRbOSxXPJg1rZwLgHcyCBwz/dRwIAiCwCcfN0/8AAAAEc3NoOg==";
    @SuppressWarnings("checkstyle:linelength")
    private static final String SIG_FOR_MSG1_WITH_TOUCH
            = "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAQH1/F/bSQIsjPJ/yk5iMv+Ym+aOuwY+gFhfcEQuMBYSNs3o4QaGSzYxO0vhPjOsQjsFkzi7NDNx5vEhDHnwFMw8BEjRWeA==";
    @SuppressWarnings("checkstyle:linelength")
    private static final String SIG_FOR_MSG2_WITH_NO_TOUCH
            = "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAQOKFNjIjHLUXef5t+OSlLIV4OqnUkOShjvOltEOnlWT2fLj3Ue9uSMXr6Cui98sTyTPeUbwSvs5SM8Wb0rEmVwEAEjRWeA==";

    private static final Base64.Decoder B64_DECODER = Base64.getDecoder();

    public SignatureSkED25519Test() {
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
        SignatureSkED25519 verifier = new SignatureSkED25519();
        verifier.initVerifier(null, publicKey);
        verifier.update(null, msg);
        assertEquals(expected, verifier.verify(null, sig));
    }
}
