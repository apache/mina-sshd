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
package org.apache.sshd.common.kex;

import java.security.GeneralSecurityException;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.util.security.KEM;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * All built in key encapsulation methods (KEM).
 */
public enum BuiltinKEM implements KEM, NamedResource, OptionalFeature {

    mlkem768("mlkem768", KEM.ML_KEM_768),

    mlkem1024("mlkem1024", KEM.ML_KEM_1024),

    sntrup761("sntrup761", KEM.SNTRUP_761);

    private String name;

    private KEM kem;

    BuiltinKEM(String name, String algorithm) {
        this.name = name;
        KEM k;
        try {
            k = SecurityUtils.getKEM(algorithm);
        } catch (GeneralSecurityException e) {
            k = null;
        }
        this.kem = k;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean isSupported() {
        return kem != null && kem.isSupported();
    }

    @Override
    public Client getClient() {
        return kem.getClient();
    }

    @Override
    public Server getServer() {
        return kem.getServer();
    }
}
