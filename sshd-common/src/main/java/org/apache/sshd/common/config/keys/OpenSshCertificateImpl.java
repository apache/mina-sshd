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

import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class OpenSshCertificateImpl implements OpenSshCertificate {

    private static final long serialVersionUID = -3592634724148744943L;

    private String keyType;
    private byte[] nonce;
    private PublicKey certificatePublicKey;
    private long serial;
    // Keep storing the raw code here to not break serialization
    private int type;
    private String id;
    private Collection<String> principals;
    // match ssh-keygen behavior where the default is the epoch
    private long validAfter = OpenSshCertificate.MIN_EPOCH;
    // match ssh-keygen behavior where the default would be forever
    private long validBefore = OpenSshCertificate.INFINITY;
    private SortedMap<String, String> criticalOptions;
    private SortedMap<String, String> extensions;
    private String reserved;
    private PublicKey caPubKey;
    private byte[] message;
    private byte[] signature;

    public OpenSshCertificateImpl() {
        super();
    }

    @Override
    public String getRawKeyType() {
        return GenericUtils.isEmpty(keyType) ? null : keyType.split("@")[0].substring(0, keyType.indexOf("-cert"));
    }

    @Override
    public byte[] getNonce() {
        return nonce;
    }

    @Override
    public String getKeyType() {
        return keyType;
    }

    @Override
    public PublicKey getCertPubKey() {
        return certificatePublicKey;
    }

    @Override
    public long getSerial() {
        return serial;
    }

    @Override
    public Type getType() {
        return Type.fromCode(type);
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public Collection<String> getPrincipals() {
        return principals == null ? Collections.emptyList() : principals;
    }

    @Override
    public long getValidAfter() {
        return validAfter;
    }

    @Override
    public long getValidBefore() {
        return validBefore;
    }

    @Override
    public List<CertificateOption> getCriticalOptions() {
        if (criticalOptions == null || criticalOptions.isEmpty()) {
            return Collections.emptyList();
        }
        List<CertificateOption> list = new ArrayList<>(criticalOptions.size());
        criticalOptions.forEach((k, v) -> list.add(new CertificateOption(k, v)));
        return Collections.unmodifiableList(list);
    }

    @Override
    public SortedMap<String, String> getCriticalOptionsMap() {
        return criticalOptions == null ? Collections.emptySortedMap() : Collections.unmodifiableSortedMap(criticalOptions);
    }

    @Override
    public List<CertificateOption> getExtensions() {
        if (extensions == null || extensions.isEmpty()) {
            return Collections.emptyList();
        }
        List<CertificateOption> list = new ArrayList<>(extensions.size());
        extensions.forEach((k, v) -> list.add(new CertificateOption(k, v)));
        return Collections.unmodifiableList(list);
    }

    @Override
    public SortedMap<String, String> getExtensionsMap() {
        return extensions == null ? Collections.emptySortedMap() : Collections.unmodifiableSortedMap(extensions);
    }

    @Override
    public String getReserved() {
        return reserved;
    }

    @Override
    public PublicKey getCaPubKey() {
        return caPubKey;
    }

    @Override
    public byte[] getMessage() {
        return message;
    }

    @Override
    public byte[] getSignature() {
        return signature;
    }

    @Override
    public byte[] getRawSignature() {
        if (signature == null) {
            return null;
        }
        ByteArrayBuffer buffer = new ByteArrayBuffer(signature);
        buffer.getString();
        return buffer.getBytes();
    }

    @Override
    public String getSignatureAlgorithm() {
        return NumberUtils.isEmpty(signature) ? null : new ByteArrayBuffer(signature).getString();
    }

    @Override
    public String getAlgorithm() {
        return null;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return GenericUtils.EMPTY_BYTE_ARRAY;
    }

    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }

    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    public void setCertPubKey(PublicKey certificatePublicKey) {
        this.certificatePublicKey = certificatePublicKey;
    }

    public void setSerial(long serial) {
        this.serial = serial;
    }

    public void setType(Type type) {
        this.type = type.getCode();
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setPrincipals(Collection<String> principals) {
        this.principals = principals;
    }

    public void setValidAfter(long validAfter) {
        this.validAfter = validAfter;
    }

    /**
     * If null, uses {@link OpenSshCertificate#MIN_EPOCH}
     *
     * @param validAfter {@link Instant} to use for validAfter
     */
    public void setValidAfter(Instant validAfter) {
        if (validAfter == null) {
            setValidAfter(OpenSshCertificate.MIN_EPOCH);
        } else if (Instant.EPOCH.compareTo(validAfter) <= 0) {
            setValidAfter(validAfter.getEpochSecond());
        } else {
            throw new IllegalArgumentException("Valid-after cannot be < epoch");
        }
    }

    public void setValidBefore(long validBefore) {
        this.validBefore = validBefore;
    }

    /**
     * If null, uses {@link OpenSshCertificate#INFINITY}
     *
     * @param validBefore {@link Instant} to use for validBefore
     */
    public void setValidBefore(Instant validBefore) {
        if (validBefore == null) {
            setValidBefore(OpenSshCertificate.INFINITY);
        } else if (Instant.EPOCH.compareTo(validBefore) <= 0) {
            setValidBefore(validBefore.getEpochSecond());
        } else {
            throw new IllegalArgumentException("Valid-before cannot be < epoch");
        }
    }

    /**
     * Sets the critical options of the certificate, overriding any options set earlier.
     *
     * @param criticalOptions to set; may be {@code null} or empty to remove all previously set options
     */
    public void setCriticalOptions(List<CertificateOption> criticalOptions) {
        if (criticalOptions == null || criticalOptions.isEmpty()) {
            this.criticalOptions = null;
        } else {
            this.criticalOptions = new TreeMap<>();
            for (CertificateOption option : criticalOptions) {
                String data = option.getData();
                this.criticalOptions.put(option.getName(), data == null ? "" : data);
            }
        }
    }

    /**
     * Sets the critical options of the certificate, overriding any options set earlier.
     *
     * @param criticalOptions to set; may be {@code null} or empty to remove all previously set options
     */
    public void setCriticalOptions(Map<String, String> criticalOptions) {
        if (criticalOptions == null || criticalOptions.isEmpty()) {
            this.criticalOptions = null;
        } else {
            this.criticalOptions = new TreeMap<>();
            criticalOptions.forEach((k, v) -> {
                String data = v == null ? "" : v;
                this.criticalOptions.put(k, data);
            });
        }
    }

    /**
     * Adds a critical option to the certificate, or removes it if {@code value == null}. To add an option with an empty
     * value, use an empty string as value. If the certificate already has an option with the given name it is replaced.
     *
     * @param  name  of the option to set
     * @param  value of the option
     * @return       {@code true} if the map did not contain the name; {@code false} if it did
     */
    public boolean addCriticalOption(String name, String value) {
        String key = ValidateUtils.checkNotNullAndNotEmpty(name, "Critical option name must be set");
        if (value == null) {
            if (criticalOptions == null) {
                return true;
            }
            return criticalOptions.remove(key) == null;
        }
        if (criticalOptions == null) {
            criticalOptions = new TreeMap<>();
        }
        return criticalOptions.put(key, value) == null;
    }

    /**
     * Sets the extensions of the certificate, overriding any extensions set earlier.
     *
     * @param extensions to set; may be {@code null} or empty to remove all previously set extensions
     */
    public void setExtensions(List<CertificateOption> extensions) {
        if (extensions == null || extensions.isEmpty()) {
            this.extensions = null;
        } else {
            this.extensions = new TreeMap<>();
            for (CertificateOption option : extensions) {
                String data = option.getData();
                this.extensions.put(option.getName(), data == null ? "" : data);
            }
        }
    }

    /**
     * Sets the extensions of the certificate, overriding any extensions set earlier.
     *
     * @param extensions to set; may be {@code null} or empty to remove all previously set extensions
     */
    public void setExtensions(Map<String, String> extensions) {
        if (extensions == null || extensions.isEmpty()) {
            this.extensions = null;
        } else {
            this.extensions = new TreeMap<>();
            extensions.forEach((k, v) -> {
                String data = v == null ? "" : v;
                this.extensions.put(k, data);
            });
        }
    }

    /**
     * Adds an extension to the certificate, or removes it if {@code value == null}. To add an extension with an empty
     * value, use an empty string as value. If the certificate already has an extension with the given name it is
     * replaced.
     *
     * @param  name  of the extension to set
     * @param  value of the extension
     * @return       {@code true} if the map did not contain the name; {@code false} if it did
     */
    public boolean addExtension(String name, String value) {
        String key = ValidateUtils.checkNotNullAndNotEmpty(name, "Extension name must be set");
        if (value == null) {
            if (extensions == null) {
                return true;
            }
            return extensions.remove(key) == null;
        }
        if (extensions == null) {
            extensions = new TreeMap<>();
        }
        return extensions.put(key, value) == null;
    }

    public void setReserved(String reserved) {
        this.reserved = reserved;
    }

    public void setCaPubKey(PublicKey caPubKey) {
        this.caPubKey = caPubKey;
    }

    public void setMessage(byte[] message) {
        this.message = message;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    private static String toDate(long timestamp) {
        if (timestamp < 0) {
            return "infinity";
        }
        Date date = new Date(TimeUnit.SECONDS.toMillis(timestamp));
        return date.toString();
    }

    @Override
    public String toString() {
        return getKeyType()
               + "[id=" + getId()
               + ", serial=" + getSerial()
               + ", type=" + getType()
               + ", validAfter=" + toDate(getValidAfter())
               + ", validBefore=" + toDate(getValidBefore())
               + "]";
    }

}
