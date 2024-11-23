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
package org.apache.sshd.common.util.security.eddsa;

import net.i2p.crypto.eddsa.EdDSAEngine;
import org.apache.sshd.common.util.security.eddsa.generic.GenericSignatureEd25519;

/**
 * An implementation of {@link GenericSignatureEd25519} tied to the {@code net.i2p.crypto} EdDSA security provider.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SignatureEd25519 extends GenericSignatureEd25519 {
    public SignatureEd25519() {
        super(EdDSAEngine.SIGNATURE_ALGORITHM);
    }
}
