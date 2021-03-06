/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package jvm.library;

import org.junit.Test;
import static org.junit.Assert.*;
 
import java.io.IOException;  
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.operator.OperatorCreationException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;


public class LibraryTest {
    @Test public void testGenerateKeyPair() throws NoSuchAlgorithmException, IOException, OperatorCreationException, InvalidKeySpecException  {
        KeyPair keyPair = Library.generateKeyPair();
        PrivateKey pvtKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();
        assertTrue("savePrivateKey should return 'true'",Library.savePrivateKey(pvtKey, "pvtT.key"));
        assertTrue("savePublicKey should return 'true'",Library.savePublicKey(pubKey, "pubT.key"));

    }

    @Test public void testEncryptDecrypt(){
        KeyPair keyPair = Library.generateKeyPair();
        PrivateKey pvtKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();
        String enc = Library.encrypt(pubKey, "abcde");
        System.out.println(enc);
        String dec = Library.decrypt(pvtKey, enc);
        System.out.println(dec);
        assertTrue("decrypted value should equal to 'abcde'", Objects.equals(dec, "abcde"));
    }

    @Test public void testKeyImport() throws Exception {
            PublicKey pubKey = Library.importPublicKey("pubT.key");
            PrivateKey pvtKey = Library.importPrivateKey("pvtT.key");
            String enc = Library.encrypt(pubKey, "abcde");
            System.out.println(enc);
            String dec = Library.decrypt(pvtKey, enc);
            System.out.println(dec);
            assertTrue("decrypted value should equal to 'abcde'", Objects.equals(dec, "abcde"));
    }
}
