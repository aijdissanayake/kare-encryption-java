package jvm.library;

// import java.security.KeyPair;
// import java.security.KeyPairGenerator;
// import java.security.NoSuchAlgorithmException;
// import java.security.PrivateKey;
// import java.security.PublicKey;
// import javax.crypto.Cipher;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
// import java.nio.file.Files;
// import java.nio.file.Paths;
// import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.io.IOException;

// import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

public class Library {

    private static final String algorithm = "RSA";	

	public static boolean generateKeyPair(String publicKeyOutput, String privateKeyOutput) {
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
			keyGen.initialize(2048);

			final KeyPair key = keyGen.generateKeyPair();

			// try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(new File(publicKeyOutput)))) {
			// 	dos.write(key.getPublic().getEncoded());
			// }

			// try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(new File(privateKeyOutput)))) {
			// 	dos.write(key.getPrivate().getEncoded());
			// }
			Library.save(key, publicKeyOutput, privateKeyOutput);
			return true;

		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return false;
    }

    
    public static void save(KeyPair keyPair, String publicKeyOutput, String privateKeyOutput) throws IOException {
        final PrivateKey privateKey = keyPair.getPrivate();
        final PublicKey publicKey = keyPair.getPublic();
    
        // Store Public Key
        final X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        try (FileOutputStream fos = new FileOutputStream(new File(publicKeyOutput))) {
            String pubKeyString = "-----BEGIN RSA PUBLIC KEY-----\n" +
            DatatypeConverter.printBase64Binary(x509EncodedKeySpec.getEncoded()) +
            "\n-----END RSA PUBLIC KEY-----\n";
            fos.write(pubKeyString.getBytes());
        }
    
        // Store Private Key.
        final PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        try (FileOutputStream fos = new FileOutputStream(new File(privateKeyOutput))) {
            String pvtKeyString = "-----BEGIN RSA PRIVATE KEY-----\n" +
            DatatypeConverter.printBase64Binary(pkcs8EncodedKeySpec.getEncoded()) +
            "\n-----END RSA PRIVATE KEY-----\n";
            fos.write(pvtKeyString.getBytes());
        }
    }

    
}
