package jvm.library;

// import java.security.KeyPair;
// import java.security.KeyPairGenerator;
// import java.security.NoSuchAlgorithmException;
// import java.security.PrivateKey;
// import java.security.PublicKey;
import javax.crypto.Cipher;
// import java.io.DataOutputStream;
// import java.io.File;
// import java.io.FileOutputStream;
// import java.security.KeyPair;
// import java.security.KeyPairGenerator;
// import java.security.Key;
// import java.security.SecureRandom;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
// import java.security.interfaces.RSAPrivateKey;
// import java.security.interfaces.RSAPublicKey;
// import java.io.IOException;
// import java.io.FileNotFoundException;
// import java.io.Writer;
// import java.io.FileWriter;

// import javax.crypto.Cipher;
// import javax.xml.bind.DatatypeConverter;
import java.util.Base64;
 
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;  
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.io.pem.PemObject; 

   
import java.io.FileOutputStream;  
import java.io.IOException;  
import java.io.StringWriter;  
import java.security.KeyPair;  
import java.security.KeyPairGenerator;  
import java.security.NoSuchAlgorithmException;  
import java.security.SecureRandom;  
import java.security.spec.InvalidKeySpecException;

// import org.bouncycastle.asn1.ASN1Encodable;
// import org.bouncycastle.asn1.ASN1Primitive;
// import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
// import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
// import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
// import org.bouncycastle.x509.X509V3CertificateGenerator;

public class Library {

    private static final String algorithm = "RSA";


    public static KeyPair generateKeyPair(int keyLength){
        try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
			keyGen.initialize(keyLength, new SecureRandom());
			final KeyPair keyPair = keyGen.generateKeyPair();
			return keyPair;

		} catch (Exception e) {
			e.printStackTrace();
		}		
		return null;
    }

    public static KeyPair generateKeyPair(){
        return generateKeyPair(2048);
    }

    public static boolean savePrivateKey(PrivateKey privateKey, String fileSavePath) throws NoSuchAlgorithmException, IOException, OperatorCreationException, InvalidKeySpecException {
        try{
            JcaPKCS8Generator gen1 = new JcaPKCS8Generator(privateKey, null);  
            PemObject obj1 = gen1.generate();  
            StringWriter sw1 = new StringWriter();  
            try (JcaPEMWriter pw = new JcaPEMWriter(sw1)) {  
            pw.writeObject(obj1);  
            }  
            String pkcs8Key1 = sw1.toString();  
            FileOutputStream fos1 = new FileOutputStream(fileSavePath);  
            fos1.write(pkcs8Key1.getBytes());  
            fos1.flush();  
            fos1.close(); 

            return true;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static boolean savePublicKey(PublicKey publicKey, String fileSavePath) throws NoSuchAlgorithmException, IOException, OperatorCreationException, InvalidKeySpecException {
        try{
            byte[] pubBytes = publicKey.getEncoded();
            PemObject pemObject = new PemObject("PUBLIC KEY", pubBytes);
            StringWriter stringWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(stringWriter);
            pemWriter.writeObject(pemObject);
            pemWriter.close();
            String pemString = stringWriter.toString();
            FileOutputStream fos2 = new FileOutputStream(fileSavePath);  
            fos2.write(pemString.getBytes());  
            fos2.flush();  
            fos2.close();

            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static String encrypt(PublicKey key, String data) {		
		try {
			final Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return  Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));

		} catch (Exception e) {
            e.printStackTrace();
		}
		return null;
    }
    
    public static String decrypt(PrivateKey key, String encryptedData) {
		try {
			final Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] enc64Bytes = encryptedData.getBytes();
            byte[] encBytes = Base64.getDecoder().decode(enc64Bytes);
			return new String(cipher.doFinal(encBytes));

		} catch (Exception e) {
            e.printStackTrace();
		}
		return null;
    }
    
    // refine
    public static PublicKey getPublicKey(String publicKeyPath) throws Exception {
		return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(Files.readAllBytes(Paths.get(publicKeyPath))));
    }
    
    public static PrivateKey getPrivateKey(String privateKeyPath) throws Exception {
		return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get(privateKeyPath))));
    }
    
    public static PrivateKey getPrivateKeyString(String keyString) throws Exception{
        // Remove the first and last lines

        String privKeyPEM = keyString.replace("-----BEGIN RSA PRIVATE KEY-----\n", "");
        privKeyPEM = privKeyPEM.replace("-----END RSA PRIVATE KEY-----", "");
        System.out.println(privKeyPEM);

        // Base64 decode the data

        byte [] encoded = org.bouncycastle.util.encoders.Base64.decode(privKeyPEM);

        // PKCS8 decode the encoded RSA private key

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        return privKey;

    }

    public static PublicKey getPublicKeyFile(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static PrivateKey getPrivateKeyFile(String filename) throws Exception {  
      byte[] keyBytes = Files.readAllBytes(Paths.get(filename));  
      PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return kf.generatePrivate(spec);
    }

}
