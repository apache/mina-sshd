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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.DigestFactory;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class KeyUtilsFingerprintGenerationTest extends JUnitTestSupport {
    private final PublicKey key;
    private final DigestFactory digestFactory;
    private final String expected;

    public KeyUtilsFingerprintGenerationTest(PublicKey key, DigestFactory digestFactory, String expected) {
        this.key = key;
        this.digestFactory = digestFactory;
        this.expected = expected;
    }

    @Parameters(name = "key={0}, digestFactory={1}, expected={2}")
    public static Collection<Object[]> parameters() throws IOException, GeneralSecurityException {
        List<? extends Map.Entry<String, List<? extends Map.Entry<DigestFactory, String>>>> keyEntries
                = Collections.unmodifiableList(Arrays.asList(
                        new SimpleImmutableEntry<>(
                        // CHECKSTYLE:OFF
                    "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAxr3N5fkt966xJINl0hH7Q6lLDRR1D0yMjcXCE5roE9VFut2ctGFuo90TCOxkPOMnwzw"
                    + "ConeyScVF4ConZeWsxbG9VtRh61IeZ6R5P5ZTvE9xPdZBgIEWvU1bRfrrOfSMihqF98pODspE6NoTtND2eglwSGwxcYFmpdTAmu+"
                    + "8qgxgGxlEaaCjqwdiNPZhygrH81Mv2ruolNeZkn4Bj+wFFmZTD/waN1pQaMf+SO1+kEYIYFNl5+8JRGuUcr8MhHHJB+gwqMTF2BSB"
                    + "VITJzZUiQR0TMtkK6Vbs7yt1F9hhzDzAFDwhV+rsfNQaOHpl3zP07qH+/99A0XG1CVcEdHqVMw== lgoldstein@LGOLDSTEIN-WIN7",
                    // CHECKSTYLE:ON
                                Arrays.asList(
                                        new SimpleImmutableEntry<>(
                                                BuiltinDigests.md5,
                                                "MD5:24:32:3c:80:01:b3:e1:fa:7c:53:ca:e3:e8:4e:c6:8e"),
                                        new SimpleImmutableEntry<>(
                                                BuiltinDigests.sha256,
                                                "SHA256:1wNOZO+/XgNGJMx8UUJst33V+bBMTz5EcL0B6y2iRv0"))),
                        new SimpleImmutableEntry<>(
                        // CHECKSTYLE:OFF
                    "ssh-dss AAAAB3NzaC1kc3MAAACBAMg/IxsG5BxnF5gM7IKqqR0rftxZC+n5GlbO+J4H+iIb/KR8NBehkxG3CrBZMF96M2K1sEGYLob+"
                    + "3k4r71oWaPul8n5rt9kpd+JSq4iD2ygOyg6Kd1/YDBHoxneizy6I/bGsLwhAAKWcRNrXmYVKGzhrhvZWN12AJDq2mGdj3szLAAAAFQ"
                    + "D7a2MltdUSF7FU3//SpW4WGjZbeQAAAIBf0nNsfKQL/TEMo7IpTrEMg5V0RnSigCX0+yUERS42GW/ZeCZBJw7oL2XZbuBtu63vMjDg"
                    + "Vpnb92BdrcPgjJ7EFW6DlcyeuywStmg1ygXmDR2AQCxv0eX2CQgrdUczmRa155SDVUTvTQlO1IyKx0vwKAh1H7E3yJUfkTAJstbGYQ"
                    + "AAAIEAtv+cdRfNevYFkp55jVqazc8zRLvfb64jzgc5oSJVc64kFs4yx+abYpGX9WxNxDlG6g2WiY8voDBB0YnUJsn0kVRjBKX9OceR"
                    + "OxrfT4K4dVbQZsdt+SLaXWL4lGJFrFZL3LZqvySvq6xfhJfakQDDivW4hUOhFPXPHrE5/Ia3T7A= dsa-key-20130709",
                    // CHECKSTYLE:ON
                                Arrays.asList(
                                        new SimpleImmutableEntry<>(
                                                BuiltinDigests.md5,
                                                "MD5:fb:29:14:8d:94:f9:1d:cf:6b:0e:a4:35:1d:83:44:2f"),
                                        new SimpleImmutableEntry<>(
                                                BuiltinDigests.sha256,
                                                "SHA256:grxw4KhY1cK6eOczBWs7tDVvo9V0PQw4E1wN1gJvHlw"))),
                        new SimpleImmutableEntry<>(
                        // CHECKSTYLE:OFF
                    "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBFImZtcTj842stlcVHLFBFxTEx7lu3j"
                    + "W9aZCvd0r9fUNKZ6LbRPh6l1oJ4ozArnw7XreQBUc5oNd9HB5RNJ8jl1nWXY5cXBA7McZrKZrYmk+zxNhH6UL+kMLaJkyngJHQw== root@osv-linux",
                    // CHECKSTYLE:ON
                                Arrays.asList(
                                        new SimpleImmutableEntry<>(
                                                BuiltinDigests.md5,
                                                "MD5:e6:dc:a2:4f:5b:11:b2:3c:0f:e8:f6:d8:d1:01:e9:d3"),
                                        new SimpleImmutableEntry<>(
                                                BuiltinDigests.sha512,
                                                "SHA512:4w6ZB78tmFWhpN2J50Ok6WeMJhZp1X0xN0EKWxZmRLcYDbCWhyJDe8lgrQKWqdTCMZ5aNEBl9xQUklcC5Gt2jg")))));

        List<Object[]> ret = new ArrayList<>();
        for (Map.Entry<String, ? extends Collection<? extends Map.Entry<DigestFactory, String>>> kentry : keyEntries) {
            String keyValue = kentry.getKey();
            try {
                PublicKeyEntry keyEntry = PublicKeyEntry.parsePublicKeyEntry(keyValue);
                PublicKey key = keyEntry.resolvePublicKey(
                        null, Collections.emptyMap(), PublicKeyEntryResolver.FAILING);
                for (Map.Entry<DigestFactory, String> dentry : kentry.getValue()) {
                    DigestFactory factory = dentry.getKey();
                    String fingerprint = dentry.getValue();
                    if (!factory.isSupported()) {
                        System.out.println("Skip unsupported digest: " + fingerprint);
                        continue;
                    }

                    ret.add(new Object[] { key, factory, fingerprint });
                }
            } catch (InvalidKeySpecException e) {
                System.out.println("Skip unsupported key: " + keyValue);
            }
        }

        return ret;
    }

    @Test
    public void testFingerprint() throws Exception {
        String name = digestFactory.getName();
        assertEquals(
                String.format("Fingerprint does not match for digest %s", name),
                expected,
                KeyUtils.getFingerPrint(digestFactory, key));
        assertEquals(
                String.format("Fingerprint check failed for digest %s", name),
                new SimpleImmutableEntry<>(true, expected),
                KeyUtils.checkFingerPrint(expected, digestFactory, key));
        assertEquals(
                String.format("Fingerprint check succeeded for invalid digest %s", name),
                new SimpleImmutableEntry<>(false, expected),
                KeyUtils.checkFingerPrint(expected + "A", digestFactory, key));
    }
}
