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

package org.apache.sshd.common.config.keys.loader.openssh;

import java.util.function.Predicate;

import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class OpenSSHParserContext {
    public static final String NONE_CIPHER = "none";
    public static final Predicate<String> IS_NONE_CIPHER = c -> GenericUtils.isEmpty(c) || NONE_CIPHER.equalsIgnoreCase(c);

    private String cipherName;
    private OpenSSHKdfOptions kdfOptions;

    public OpenSSHParserContext() {
        super();
    }

    public OpenSSHParserContext(String cipherName, OpenSSHKdfOptions kdfOptions) {
        setCipherName(cipherName);
        setKdfOptions(kdfOptions);
    }

    public boolean isEncrypted() {
        if (!IS_NONE_CIPHER.test(getCipherName())) {
            return true;
        }

        OpenSSHKdfOptions options = getKdfOptions();
        return (options != null) && options.isEncrypted();
    }

    public String getCipherName() {
        return cipherName;
    }

    public void setCipherName(String cipherName) {
        this.cipherName = cipherName;
    }

    public OpenSSHKdfOptions getKdfOptions() {
        return kdfOptions;
    }

    public void setKdfOptions(OpenSSHKdfOptions kdfOptions) {
        this.kdfOptions = kdfOptions;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[cipher=" + getCipherName()
               + ", kdfOptions=" + getKdfOptions()
               + "]";
    }
}
