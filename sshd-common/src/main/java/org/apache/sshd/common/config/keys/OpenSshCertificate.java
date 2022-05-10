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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.util.ValidateUtils;

/**
 * An OpenSSH certificate key as specified by OpenSSH.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <a href= "https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD">PROTOCOL.certkeys</a>
 */
public interface OpenSshCertificate extends PublicKey, PrivateKey {

    /**
     * {@link OpenSshCertificate}s have a type indicating whether the certificate if for a host key (certifying a host
     * identity) or for a user key (certifying a user identity). <B>Note:</B> values order is significant
     */
    enum Type {
        /** User key certificate. */
        USER,
        /** Host key certificate. */
        HOST,
        ;

        public static final List<Type> VALUES = Collections.unmodifiableList(Arrays.asList(values()));

        public int getCode() {
            return ordinal() + 1;
        }

        public static Type fromCode(int code) {
            ValidateUtils.checkTrue((code > 0) && (code <= VALUES.size()),
                    "Invalid type code: %d", code);
            return VALUES.get(code - 1);
        }
    }

    /**
     * The minimal {@link #getValidAfter()} or {@link #getValidBefore()} value, corresponding to {@code Instant#EPOCH}.
     */
    long MIN_EPOCH = 0L;

    /**
     * The maximum {@link #getValidAfter()} or {@link #getValidBefore()} value.
     * <p>
     * Note that timestamps in OpenSSH certificates are <em>unsigned</em> 64-bit values.
     * </p>
     *
     * @see #isValidNow(OpenSshCertificate)
     */
    long INFINITY = 0xffff_ffff_ffff_ffffL;

    /**
     * Retrieves the raw SSH key type of this certificate.
     *
     * @return the key type, for instance "ssh-rsa" for a "ssh-rsa-cert-v01@openssh.com" certificate
     */
    String getRawKeyType();

    /**
     * Retrieves the nonce of this certificate.
     *
     * @return the nonce.
     */
    byte[] getNonce();

    /**
     * Retrieves the SSH key type of this certificate.
     *
     * @return the key type, for instance "ssh-rsa-cert-v01@openssh.com"
     */
    String getKeyType();

    /**
     * Retrieves the certified public key.
     *
     * @return the {@link PublicKey}
     */
    PublicKey getCertPubKey();

    /**
     * Retrieves the serial number of this certificate.
     *
     * @return the serial number
     */
    long getSerial();

    /**
     * Retrieves the type of certificate.
     *
     * @return the {@link Type}
     */
    Type getType();

    /**
     * Retrieves a free-form text set by the CA when the certificate was generated; intended to identify the identity
     * principal in log message.
     *
     * @return the id; never {@code null} but may be empty.
     */
    String getId();

    /**
     * Retrieves the principals mentioned in the certificate.
     *
     * @return the collection of principals, never {@code null} but possibly empty
     */
    Collection<String> getPrincipals();

    /**
     * Retrieves the time in number of seconds since the {@link java.time.Instant#EPOCH} at which this certificate
     * becomes or became valid.
     *
     * @return the number of seconds since the {@link java.time.Instant#EPOCH} <em>as an unsigned 64bit value</em>
     * @see    #isValidNow(OpenSshCertificate)
     */
    long getValidAfter();

    /**
     * Retrieves the time in number of seconds since the {@link java.time.Instant#EPOCH} at which this certificate
     * becomes or became invalid.
     *
     * @return the number of seconds since the {@link java.time.Instant#EPOCH} <em>as an unsigned 64bit value</em>
     * @see    #isValidNow(OpenSshCertificate)
     */
    long getValidBefore();

    /**
     * Retrieves the critical options set in the certificate.
     *
     * @return the critical options as a list, never {@code null} but possibly empty
     */
    List<CertificateOption> getCriticalOptions();

    /**
     * Retrieves the extensions set in the certificate.
     *
     * @return the extensions as a list, never {@code null} but possibly empty
     */
    List<CertificateOption> getExtensions();

    /**
     * Retrieves the "reserved" field of the certificate. OpenSSH currently doesn't use it and ignores it.
     *
     * @return the "reserved" field.
     */
    String getReserved();

    /**
     * Retrieves the CA public key of this certificate.
     *
     * @return the {@link PublicKey}
     */
    PublicKey getCaPubKey();

    /**
     * Retrieves the raw byte content of the certificate, minus the signature. This is the data that was signed.
     *
     * @return the part of the certificate raw data that was signed
     */
    byte[] getMessage();

    /**
     * Retrieves the signature of the certificate, including the signature algorithm.
     *
     * @return the signature bytes
     * @see    #getRawSignature()
     */
    byte[] getSignature();

    /**
     * Retrieves the signature algorithm used for the signature.
     *
     * @return the signature algorithm as recorded in the certificate
     */
    String getSignatureAlgorithm();

    /**
     * Retrieves the raw signature bytes, without the signature algorithm.
     *
     * @return the signature bytes
     * @see    #getSignature()
     */
    byte[] getRawSignature();

    /**
     * Determines whether the given {@link OpenSshCertificate} is valid at the current local system time.
     *
     * @param  cert to check
     * @return      {@code true} if the certificate is valid according to its timestamps, {@code false} otherwise
     */
    static boolean isValidNow(OpenSshCertificate cert) {
        long now = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
        return Long.compareUnsigned(cert.getValidAfter(), now) <= 0
                && Long.compareUnsigned(now, cert.getValidBefore()) < 0;
    }

    /**
     * Certificate Options are a set of bytes that is
     *
     * <pre>
     * [overall length][name(string)][[length of buffer][[length of string][data(string)]]]...
     * </pre>
     * <p>
     * Where each Certificate Option is encoded as a name (string) and data (string packed in a buffer). The entire name
     * (string) + data (buffer) are added as bytes (which will get a length prefix).
     * </p>
     *
     * @see <a href=
     *      "https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys#L221-L319">PROTOCOL.certkeys</a>
     */
    class CertificateOption {

        private final String name;
        private final String data;

        /**
         * Creates a new {@link CertificateOption} with the given name and data.
         *
         * @param name of the option; must be neither {@code null} nor empty
         * @param data for the option; may be {@code null} or empty
         */
        public CertificateOption(String name, String data) {
            this.name = ValidateUtils.checkNotNullAndNotEmpty(name, "CertificateOption name must be set");
            this.data = data;
        }

        /**
         * Creates a new {@link CertificateOption} with a name without data.
         *
         * @param name of the option; must be neither {@code null} nor empty
         */
        public CertificateOption(String name) {
            this(name, null);
        }

        /**
         * Retrieves the name.
         *
         * @return the name, never {@code null}
         */
        public final String getName() {
            return name;
        }

        /**
         * Retrieves the data.
         *
         * @return the data, may be{@code null} or empty
         */
        public final String getData() {
            return data;
        }

        @Override
        public String toString() {
            return "CertificateOption{name='" + name + "', data='" + data + "'}";
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }
            if (obj == this) {
                return true;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }

            CertificateOption other = (CertificateOption) obj;
            return Objects.equals(name, other.name) && Objects.equals(data, other.data);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, data);
        }
    }
}
