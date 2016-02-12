package org.apache.sshd.common.signature;

import org.apache.mina.util.Base64;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.security.*;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;

/**
 * Created by eugene.petrenko@gmail.com
 */
public class SignatureRSATest {
    @Test
    public void testLeadingZeroes_BC() throws Throwable {
        byte[] msg = Base64.decodeBase64("AAAAFPHgK1MeV9zNnok3pwNJhCd8SONqMgAAAAlidWlsZHVzZXIAAAAOc3NoLWNvbm5lY3Rpb24AAAAJcHVibGlja2V5AQAAAAdzc2gtcnNhAAABFQAAAAdzc2gtcnNhAAAAASMAAAEBAMs9HO/NH/Now+6fSnESebaG4wzaYQWA1b/q1TGV1wHNtCg9fGFGVSKs0VxKF4cfVyrSLtgLjnlXQTn+Lm7xiYKGbBbsTQWOqEDaBVBsRbAkxIkpuvr6/EBxwrtDbKmSQYTJZVJSD2bZRYjGsR9gpZXPorOOKFd5EPCMHXsqnhp2hidTGH7cK6RuLk7MNnPISsY0Nbx8/ZvikiPROGcoTZ8bzUv4IaLr3veW6epSeQem8tJqhnrpTHhbLU99zf045M0Gsnk/azjjlBM+qrHZ5FNdC1kowJnLtf2Oy/rUQNpkGJtcBPT8xvreV0wLsn9t3hSxzsc0+VkDNTQRlfU+o3M=".getBytes("utf-8"));
        byte[] sig = Base64.decodeBase64("AAAAB3NzaC1yc2EAAAD/+Ntnf4qfr2J1voDS6I+u3VRjtMn+LdWJsAZfkLDxRkK1rQxP7QAjLdNqpT4CkWHp8dtoTGFlBFt6NieNJCMTA2KSOxJMZKsX7e/lHkh7C+vhQvJ9eLTKWjCxSFUrcM0NvFhmwbRCffwXSHvAKak4wbmofxQMpd+G4jZkNMz5kGpmeICBcNjRLPb7oXzuGr/g4x/3ge5Qaawqrg/gcZr/sKN6SdE8SszgKYO0SB320N4gcUoShVdLYr9uwdJ+kJoobfkUK6Or171JCctP/cu2nM79lDqVnJw/2jOG8OnTc8zRDXAh0RKoR5rOU8cOHm0Ls2MATsFdnyRU5FGUxqZ+".getBytes("utf-8"));

        byte[] exp = Base64.decodeBase64("Iw==".getBytes("utf-8"));
        byte[] mod = Base64.decodeBase64("AMs9HO/NH/Now+6fSnESebaG4wzaYQWA1b/q1TGV1wHNtCg9fGFGVSKs0VxKF4cfVyrSLtgLjnlXQTn+Lm7xiYKGbBbsTQWOqEDaBVBsRbAkxIkpuvr6/EBxwrtDbKmSQYTJZVJSD2bZRYjGsR9gpZXPorOOKFd5EPCMHXsqnhp2hidTGH7cK6RuLk7MNnPISsY0Nbx8/ZvikiPROGcoTZ8bzUv4IaLr3veW6epSeQem8tJqhnrpTHhbLU99zf045M0Gsnk/azjjlBM+qrHZ5FNdC1kowJnLtf2Oy/rUQNpkGJtcBPT8xvreV0wLsn9t3hSxzsc0+VkDNTQRlfU+o3M=".getBytes("utf-8"));

        final PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(new BigInteger(mod), new BigInteger(exp)));

        final SignatureRSA rsa = new SignatureRSA();
        rsa.initVerifier(publicKey);
        rsa.update(msg);

        Assert.assertTrue(rsa.verify(sig));
    }

    @Test
    public void testLeadingZeroes_JCE() throws Throwable {
        byte[] msg = Base64.decodeBase64("AAAAFPHgK1MeV9zNnok3pwNJhCd8SONqMgAAAAlidWlsZHVzZXIAAAAOc3NoLWNvbm5lY3Rpb24AAAAJcHVibGlja2V5AQAAAAdzc2gtcnNhAAABFQAAAAdzc2gtcnNhAAAAASMAAAEBAMs9HO/NH/Now+6fSnESebaG4wzaYQWA1b/q1TGV1wHNtCg9fGFGVSKs0VxKF4cfVyrSLtgLjnlXQTn+Lm7xiYKGbBbsTQWOqEDaBVBsRbAkxIkpuvr6/EBxwrtDbKmSQYTJZVJSD2bZRYjGsR9gpZXPorOOKFd5EPCMHXsqnhp2hidTGH7cK6RuLk7MNnPISsY0Nbx8/ZvikiPROGcoTZ8bzUv4IaLr3veW6epSeQem8tJqhnrpTHhbLU99zf045M0Gsnk/azjjlBM+qrHZ5FNdC1kowJnLtf2Oy/rUQNpkGJtcBPT8xvreV0wLsn9t3hSxzsc0+VkDNTQRlfU+o3M=".getBytes("utf-8"));
        byte[] sig = Base64.decodeBase64("AAAAB3NzaC1yc2EAAAD/+Ntnf4qfr2J1voDS6I+u3VRjtMn+LdWJsAZfkLDxRkK1rQxP7QAjLdNqpT4CkWHp8dtoTGFlBFt6NieNJCMTA2KSOxJMZKsX7e/lHkh7C+vhQvJ9eLTKWjCxSFUrcM0NvFhmwbRCffwXSHvAKak4wbmofxQMpd+G4jZkNMz5kGpmeICBcNjRLPb7oXzuGr/g4x/3ge5Qaawqrg/gcZr/sKN6SdE8SszgKYO0SB320N4gcUoShVdLYr9uwdJ+kJoobfkUK6Or171JCctP/cu2nM79lDqVnJw/2jOG8OnTc8zRDXAh0RKoR5rOU8cOHm0Ls2MATsFdnyRU5FGUxqZ+".getBytes("utf-8"));

        byte[] exp = Base64.decodeBase64("Iw==".getBytes("utf-8"));
        byte[] mod = Base64.decodeBase64("AMs9HO/NH/Now+6fSnESebaG4wzaYQWA1b/q1TGV1wHNtCg9fGFGVSKs0VxKF4cfVyrSLtgLjnlXQTn+Lm7xiYKGbBbsTQWOqEDaBVBsRbAkxIkpuvr6/EBxwrtDbKmSQYTJZVJSD2bZRYjGsR9gpZXPorOOKFd5EPCMHXsqnhp2hidTGH7cK6RuLk7MNnPISsY0Nbx8/ZvikiPROGcoTZ8bzUv4IaLr3veW6epSeQem8tJqhnrpTHhbLU99zf045M0Gsnk/azjjlBM+qrHZ5FNdC1kowJnLtf2Oy/rUQNpkGJtcBPT8xvreV0wLsn9t3hSxzsc0+VkDNTQRlfU+o3M=".getBytes("utf-8"));

        final PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(new BigInteger(mod), new BigInteger(exp)));

        final SignatureRSA rsa = new SignatureRSA() {
            @Override
            protected Signature doInitSignature() throws GeneralSecurityException {
                return java.security.Signature.getInstance(getAlgorithm());
            }
        };
        rsa.initVerifier(publicKey);
        rsa.update(msg);

        Assert.assertTrue(rsa.verify(sig));
    }
}
