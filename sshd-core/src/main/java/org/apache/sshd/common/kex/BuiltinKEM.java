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

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.OptionalFeature;

/**
 * All built in key encapsulation methods (KEM).
 */
public enum BuiltinKEM implements KeyEncapsulationMethod, NamedResource, OptionalFeature {

    mlkem768("mlkem768") {

        @Override
        public Client getClient() {
            return MLKEM.getClient(MLKEM.Parameters.mlkem768);
        }

        @Override
        public Server getServer() {
            return MLKEM.getServer(MLKEM.Parameters.mlkem768);
        }

        @Override
        public boolean isSupported() {
            return MLKEM.Parameters.mlkem768.isSupported();
        }

    },

    mlkem1024("mlkem1024") {

        @Override
        public Client getClient() {
            return MLKEM.getClient(MLKEM.Parameters.mlkem1024);
        }

        @Override
        public Server getServer() {
            return MLKEM.getServer(MLKEM.Parameters.mlkem1024);
        }

        @Override
        public boolean isSupported() {
            return MLKEM.Parameters.mlkem1024.isSupported();
        }

    },

    sntrup761("sntrup761") {

        @Override
        public Client getClient() {
            return new SNTRUP761.Client();
        }

        @Override
        public Server getServer() {
            return new SNTRUP761.Server();
        }

        @Override
        public boolean isSupported() {
            return SNTRUP761.isSupported();
        }

    };

    private String name;

    BuiltinKEM(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

}
