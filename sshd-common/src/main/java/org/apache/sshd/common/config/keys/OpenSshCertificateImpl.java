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
import java.util.Collection;
import java.util.List;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class OpenSshCertificateImpl implements OpenSshCertificate {

    private static final long serialVersionUID = -3592634724148744943L;

    private String keyType;
    private byte[] nonce;
    private PublicKey serverHostKey;
    private long serial;
    private int type;
    private String id;
    private Collection<String> principals;
    private long validAfter;
    private long validBefore;
    private List<String> criticalOptions;
    private List<String> extensions;
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
    public PublicKey getServerHostKey() {
        return serverHostKey;
    }

    @Override
    public long getSerial() {
        return serial;
    }

    @Override
    public int getType() {
        return type;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public Collection<String> getPrincipals() {
        return principals;
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
    public List<String> getCriticalOptions() {
        return criticalOptions;
    }

    @Override
    public List<String> getExtensions() {
        return extensions;
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
    public String getSignatureAlg() {
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

    public void setServerHostKey(PublicKey serverHostKey) {
        this.serverHostKey = serverHostKey;
    }

    public void setSerial(long serial) {
        this.serial = serial;
    }

    public void setType(int type) {
        this.type = type;
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

    public void setValidBefore(long validBefore) {
        this.validBefore = validBefore;
    }

    public void setCriticalOptions(List<String> criticalOptions) {
        this.criticalOptions = criticalOptions;
    }

    public void setExtensions(List<String> extensions) {
        this.extensions = extensions;
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

    @Override
    public String toString() {
        return getKeyType()
               + "[id=" + getId()
               + ", serial=" + getSerial()
               + ", type=" + getType()
               + ", validAfter=" + getValidAfterDate()
               + ", validBefore=" + getValidBeforeDate()
               + "]";
    }
}
