package jvm.library;

// import java.security.KeyPair;
// import java.security.KeyPairGenerator;
// import java.security.NoSuchAlgorithmException;
// import java.security.PrivateKey;
// import java.security.PublicKey;
// import javax.crypto.Cipher;
// import java.io.DataOutputStream;
// import java.io.File;
// import java.io.FileOutputStream;
// import java.security.KeyPair;
// import java.security.KeyPairGenerator;
import java.security.Key;
// import java.security.SecureRandom;
// import java.nio.file.Files;
// import java.nio.file.Paths;
// import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
// import java.security.spec.PKCS8EncodedKeySpec;
// import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
// import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.Writer;
import java.io.FileWriter;

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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class Library {

    private static final String algorithm = "RSA";	

	public static boolean generateKeyPair(String publicKeyOutput, String privateKeyOutput) {
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
			keyGen.initialize(2048, new SecureRandom());
			final KeyPair key = keyGen.generateKeyPair();
			save(key, publicKeyOutput, privateKeyOutput);
			return true;

		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return false;
    }

    
    private static void save(KeyPair keyPair, String publicKeyOutput, String privateKeyOutput) throws IOException {
        final PrivateKey privateKey = keyPair.getPrivate();
        final PublicKey publicKey = keyPair.getPublic();
    
        // Store Public Key
        // final X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        // try (FileOutputStream fos = new FileOutputStream(new File(publicKeyOutput))) {
        //     // String pubKeyString = "-----BEGIN RSA PUBLIC KEY-----\n" +
        //     // DatatypeConverter.printBase64Binary(x509EncodedKeySpec.getEncoded()) +
        //     // "\n-----END RSA PUBLIC KEY-----\n";
        //     // fos.write(pubKeyString.getBytes());
        //     String encodedString = "-----BEGIN PUBLIC KEY-----\n";
        //     encodedString = encodedString+Base64.getEncoder().encodeToString(x509EncodedKeySpec.getEncoded())+"\n";
        //     encodedString = encodedString+"-----END PUBLIC KEY-----\n";
        //     fos.write(encodedString.getBytes());
        // }
    
        // // Store Private Key.
        // final PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        // try (FileOutputStream fos = new FileOutputStream(new File(privateKeyOutput))) {
        //     // String pvtKeyString = "-----BEGIN RSA PRIVATE KEY-----\n" +
        //     // DatatypeConverter.printBase64Binary(pkcs8EncodedKeySpec.getEncoded()) +
        //     // "\n-----END RSA PRIVATE KEY-----\n";
        //     // fos.write(pvtKeyString.getBytes());
        //     String encodedString = "-----BEGIN PRIVATE KEY-----\n";
        //     encodedString = encodedString+Base64.getEncoder().encodeToString(pkcs8EncodedKeySpec.getEncoded())+"\n";
        //     encodedString = encodedString+"-----END PRIVATE KEY-----\n";
        //     fos.write(encodedString.getBytes());
        // }

        writePemFile((RSAPrivateKey) privateKey, "RSA PRIVATE KEY", "id_rsa.key");
		writePemFile((RSAPublicKey) publicKey, "RSA PUBLIC KEY", "id_rsa_pub.key");

    }

    private static void writePemFile(Key key, String description, String filename) throws FileNotFoundException, IOException {
        PemFile pemFile = new PemFile(key, description);
        pemFile.write(filename);
    }

    public static boolean keyGen() throws NoSuchAlgorithmException, IOException, OperatorCreationException, InvalidKeySpecException {
        try{
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");  
            kpGen.initialize(2048, new SecureRandom());  
            KeyPair keyPair = kpGen.generateKeyPair();  
        
        
            //unencrypted form of PKCS#8 file  
            JcaPKCS8Generator gen1 = new JcaPKCS8Generator(keyPair.getPrivate(), null);  
            PemObject obj1 = gen1.generate();  
            StringWriter sw1 = new StringWriter();  
            try (JcaPEMWriter pw = new JcaPEMWriter(sw1)) {  
            pw.writeObject(obj1);  
            }  
            String pkcs8Key1 = sw1.toString();  
            FileOutputStream fos1 = new FileOutputStream("pvtk.key");  
            fos1.write(pkcs8Key1.getBytes());  
            fos1.flush();  
            fos1.close(); 

            //public key
            PublicKey pub = keyPair.getPublic();
            byte[] pubBytes = pub.getEncoded();

            SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfo.getInstance(pubBytes);
            ASN1Primitive primitive = spkInfo.parsePublicKey();
            byte[] publicKeyPKCS1 = primitive.getEncoded();

            PemObject pemObject = new PemObject("RSA PUBLIC KEY", publicKeyPKCS1);
            StringWriter stringWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(stringWriter);
            pemWriter.writeObject(pemObject);
            pemWriter.close();
            String pemString = stringWriter.toString();
            FileOutputStream fos2 = new FileOutputStream("pubk.pem");  
            fos2.write(pemString.getBytes());  
            fos2.flush();  
            fos2.close();

            return true;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    } 
    

    
}
