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
package org.apache.sshd.common.cipher;

import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class ChaCha20CipherFactory implements Supplier<Cipher> {

    public static final ChaCha20CipherFactory INSTANCE = new ChaCha20CipherFactory();

    private static final Logger LOG = LoggerFactory.getLogger(ChaCha20CipherFactory.class);

    private ChaCha20CipherFactory() {
        super();
    }

    @Override
    public Cipher get() {
        LOG.debug("Using Java 8 ChaCha20 factory");
        return new ChaCha20Cipher();
    }

}
