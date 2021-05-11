package org.apache.sshd.client.opensshcerts;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.Rule;
import org.junit.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

public class ClientOpenSSHCertificatesTest {

  @Rule
  public GenericContainer sshdContainer = new GenericContainer(
    new ImageFromDockerfile("openssh-certs-sshd-test-server", false)
      .withFileFromClasspath("entrypoint.sh", "org/apache/sshd/client/opensshcerts/docker/entrypoint.sh")
      .withFileFromClasspath("sshd_config", "org/apache/sshd/client/opensshcerts/docker/sshd_config")
      .withFileFromClasspath("supervisord.conf", "org/apache/sshd/client/opensshcerts/docker/supervisord.conf")
      .withFileFromClasspath("user01_authorized_keys", "org/apache/sshd/client/opensshcerts/user/user01_authorized_keys")
      .withFileFromClasspath("user02_authorized_keys", "org/apache/sshd/client/opensshcerts/user/user02_authorized_keys")
      .withFileFromClasspath("host01", "org/apache/sshd/client/opensshcerts/host/host01")
      .withFileFromClasspath("host01.pub", "org/apache/sshd/client/opensshcerts/host/host01.pub")
      .withFileFromClasspath("host02", "org/apache/sshd/client/opensshcerts/host/host02")
      .withFileFromClasspath("host02.pub", "org/apache/sshd/client/opensshcerts/host/host02.pub")
      .withFileFromClasspath("ca.pub", "org/apache/sshd/client/opensshcerts/ca/ca.pub")
      .withFileFromClasspath("Dockerfile", "org/apache/sshd/client/opensshcerts/docker/Dockerfile")
  )
    // must be set to "/keys/host/host01" or "/keys/host/host02"
    .withEnv("SSH_HOST_KEY", "/keys/host/host01")
    .withExposedPorts(22);


  @Test
  public void sshClientCertificateRSATest() throws Exception {

    try (final InputStream certInputStream =
           Thread.currentThread().getContextClassLoader().getResourceAsStream("org/apache/sshd/client/opensshcerts/user/user01_rsa_sha2_512_2048-cert.pub")
    ) {

      final byte[] certBytes = IoUtils.toByteArray(certInputStream);
      final String certLine = GenericUtils.replaceWhitespaceAndTrim(new String(certBytes, StandardCharsets.UTF_8));

      final PublicKeyEntry certPublicKeyEntry = PublicKeyEntry.parsePublicKeyEntry(certLine);
      final PublicKey certPublicKey = certPublicKeyEntry.resolvePublicKey(null, null, null);

      final FileKeyPairProvider keyPairProvider = CommonTestSupportUtils.createTestKeyPairProvider("org/apache/sshd/client/opensshcerts/user/user01_rsa_sha2_512_2048");

      final KeyPair keypair = keyPairProvider.loadKeys(null).iterator().next();

      final PrivateKey privateKey = keypair.getPrivate();

      final SshClient client = SshClient.setUpDefaultClient();

      client.setKeyIdentityProvider(new KeyIdentityProvider() {
        @Override
        public Iterable<KeyPair> loadKeys(SessionContext session) throws IOException, GeneralSecurityException {

          final KeyPair certKeypair = new KeyPair(certPublicKey, privateKey);

          final ArrayList<KeyPair> list = new ArrayList<>();
          list.add(certKeypair);

          return list;
        }
      });

      client.start();

      try (final ClientSession session = client.connect("user01", "localhost", sshdContainer.getMappedPort(22)).verify().getSession()) {
        session.auth().verify(5L, TimeUnit.MINUTES);

        System.out.println("here");

      }


      System.out.println("here");

    }

  }

}