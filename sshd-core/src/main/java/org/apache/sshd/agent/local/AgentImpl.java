/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.agent.local;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.common.Signature;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.signature.SignatureDSA;
import org.apache.sshd.common.signature.SignatureRSA;

/**
 * A local SSH agent implementation
 */
public class AgentImpl implements SshAgent {

    private final List<Pair<KeyPair, String>> keys = new ArrayList<Pair<KeyPair, String>>();
    private boolean closed;

    public List<Pair<PublicKey, String>> getIdentities() throws IOException {
        if (closed) {
            throw new SshException("Agent closed");
        }
        List<Pair<PublicKey, String>> pks = new ArrayList<Pair<PublicKey, String>>();
        for (Pair<KeyPair, String> kp : keys) {
            pks.add(new Pair<PublicKey, String>(kp.getFirst().getPublic(), kp.getSecond()));
        }
        return pks;
    }

    public byte[] sign(PublicKey key, byte[] data) throws IOException {
        if (closed) {
            throw new SshException("Agent closed");
        }
        Pair<KeyPair, String> kp = getKeyPair(keys, key);
        if (kp == null) {
            throw new SshException("Key not found");
        }
        try {
            Signature verif;
            if (kp.getFirst().getPublic() instanceof RSAPublicKey) {
                verif = new SignatureRSA();
            } else {
                verif = new SignatureDSA();
            }
            verif.init(kp.getFirst().getPublic(), kp.getFirst().getPrivate());
            verif.update(data, 0, data.length);
            return verif.sign();
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new SshException(e);
        }
    }

    public void addIdentity(KeyPair key, String comment) throws IOException {
        if (closed) {
            throw new SshException("Agent closed");
        }
        keys.add(new Pair<KeyPair, String>(key, comment));
    }

    public void removeIdentity(PublicKey key) throws IOException {
        if (closed) {
            throw new SshException("Agent closed");
        }
        Pair<KeyPair, String> kp = getKeyPair(keys, key);
        if (kp == null) {
            throw new SshException("Key not found");
        }
        keys.remove(kp);
    }

    public void removeAllIdentities() throws IOException {
        if (closed) {
            throw new SshException("Agent closed");
        }
        keys.clear();
    }

    public void close() {
        closed = true;
        keys.clear();
    }

    protected static SshAgent.Pair<KeyPair, String> getKeyPair(List<SshAgent.Pair<KeyPair, String>> keys, PublicKey key) {
        SshAgent.Pair<KeyPair, String> kp = null;
        for (SshAgent.Pair<KeyPair, String> k : keys) {
            if (areKeyEquals(key, k.getFirst().getPublic())) {
                kp = k;
                break;
            }
        }
        return kp;
    }

    protected static boolean areKeyEquals(PublicKey k1, PublicKey k2) {
        if (k1 instanceof DSAPublicKey && k2 instanceof DSAPublicKey) {
            DSAPublicKey d1 = (DSAPublicKey) k1;
            DSAPublicKey d2 = (DSAPublicKey) k2;
            DSAParams p1 = d1.getParams();
            DSAParams p2 = d2.getParams();
            return d1.getY().equals(d2.getY())
                        && p1.getG().equals(p2.getG())
                        && p1.getP().equals(p2.getP())
                        && p1.getQ().equals(p2.getQ());
        } else if (k1 instanceof RSAPublicKey && k2 instanceof RSAPublicKey) {
            RSAPublicKey r1 = (RSAPublicKey) k1;
            RSAPublicKey r2 = (RSAPublicKey) k2;
            return r1.getModulus().equals(r2.getModulus())
                        && r1.getPublicExponent().equals(r2.getPublicExponent());
        } else {
            return false;
        }
    }

}
