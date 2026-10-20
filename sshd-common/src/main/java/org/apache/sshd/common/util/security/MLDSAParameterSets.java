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
package org.apache.sshd.common.util.security;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * ML-DSA parameter sets from FIPS 204, table 2. SSH names follow draft-sfluhrer-ssh-mldsa-08.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum MLDSAParameterSets {
    /** ML-DSA-44 parameters. */
    ML_DSA_44("ML-DSA-44", "ssh-mldsa-44", 1312, 17),
    /** ML-DSA-65 parameters. */
    ML_DSA_65("ML-DSA-65", "ssh-mldsa-65", 1952, 18),
    /** ML-DSA-87 parameters. */
    ML_DSA_87("ML-DSA-87", "ssh-mldsa-87", 2592, 19);

    /** Maximum raw public key size in bytes. */
    public static final int MAX_PUBLIC_KEY_SIZE = 2592;
    /** SSH key type names for all parameter sets. */
    public static final List<String> SSH_NAMES = Collections.unmodifiableList(Arrays.asList(
            ML_DSA_44.getSshName(), ML_DSA_65.getSshName(), ML_DSA_87.getSshName()));

    private final String jceName;
    private final String sshName;
    private final int publicKeySize;
    private final int oid;

    MLDSAParameterSets(String jceName, String sshName, int publicKeySize, int oid) {
        this.jceName = jceName;
        this.sshName = sshName;
        this.publicKeySize = publicKeySize;
        this.oid = oid;
    }

    /**
     * @return the JCA algorithm name
     */
    public String getJceName() {
        return jceName;
    }

    /**
     * @return the SSH key type name
     */
    public String getSshName() {
        return sshName;
    }

    /**
     * @return the raw public key size in bytes
     */
    public int getPublicKeySize() {
        return publicKeySize;
    }

    /**
     * @return the last arc of the RFC 9881 OID 2.16.840.1.101.3.4.3.x
     * @see    <a href="https://www.rfc-editor.org/rfc/rfc9881#section-3">RFC 9881 section 3</a>
     */
    public int getOid() {
        return oid;
    }

    /**
     * Finds a parameter set by its SSH key type name.
     *
     * @param  name the SSH key type name
     * @return      the parameter set, or {@code null} if the name is unknown
     */
    public static MLDSAParameterSets fromSshName(String name) {
        for (MLDSAParameterSets params : values()) {
            if (params.sshName.equals(name)) {
                return params;
            }
        }
        return null;
    }

    /**
     * Finds a parameter set by its JCA name, ignoring case and hyphens.
     *
     * @param  name the JCA algorithm name
     * @return      the parameter set, or {@code null} if the name is unknown
     */
    public static MLDSAParameterSets fromJceName(String name) {
        if (name != null) {
            String normalized = name.replace("-", "").toUpperCase(Locale.ROOT);
            for (MLDSAParameterSets params : values()) {
                if (params.jceName.replace("-", "").equals(normalized)) {
                    return params;
                }
            }
        }
        return null;
    }
}
