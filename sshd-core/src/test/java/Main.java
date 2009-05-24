import com.trilead.ssh2.Connection;
import com.trilead.ssh2.ServerHostKeyVerifier;
import junit.framework.TestCase;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.cipher.AES128CBC;
import org.apache.sshd.common.cipher.BlowfishCBC;
import org.apache.sshd.common.cipher.TripleDESCBC;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;

import java.io.IOException;

/**
 * @author Kohsuke Kawaguchi
 */
public class Main extends TestCase {
    public static void main(String[] args) throws IOException {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setCipherFactories(// AES 256 and 192 requires unlimited crypto, so don't use that
                new AES128CBC.Factory(),
                new TripleDESCBC.Factory(),
                new BlowfishCBC.Factory());
        sshd.setPort(0);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();

        System.out.println(sshd.getPort());

        Connection conn = new Connection("localhost",sshd.getPort());
        conn.connect(new ServerHostKeyVerifier() {
            public boolean verifyServerHostKey(String hostname, int port, String serverHostKeyAlgorithm, byte[] serverHostKey) throws Exception {
                return true;
            }
        });
        assertTrue(conn.authenticateWithPassword("root","root"));
        conn.close();
        sshd.stop();
    }
}
