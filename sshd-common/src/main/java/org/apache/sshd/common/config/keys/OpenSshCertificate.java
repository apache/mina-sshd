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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Represents and OpenSSH certificate key as specified in
 * <A HREF="https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD">PROTOCOL.certkeys</A>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface OpenSshCertificate extends PublicKey, PrivateKey {
    int SSH_CERT_TYPE_USER = 1;
    int SSH_CERT_TYPE_HOST = 2;

    String getRawKeyType();

    byte[] getNonce();

    String getKeyType();

    PublicKey getServerHostKey();

    long getSerial();

    int getType();

    String getId();

    Collection<String> getPrincipals();

    // Seconds after epoch
    long getValidAfter();

    default Date getValidAfterDate() {
        return getValidDate(getValidAfter());
    }

    // Seconds after epoch
    long getValidBefore();

    default Date getValidBeforeDate() {
        return getValidDate(getValidBefore());
    }

    List<String> getCriticalOptions();

    List<String> getExtensions();

    String getReserved();

    PublicKey getCaPubKey();

    byte[] getMessage();

    byte[] getSignature();

    String getSignatureAlg();

    static Date getValidDate(long timestamp) {
        return (timestamp == 0L) ? null : new Date(TimeUnit.SECONDS.toMillis(timestamp));
    }
}
