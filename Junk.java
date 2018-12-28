// -----BEGIN PRIVATE KEY-----"
//             +"MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCHxxBxGK1F0QjN"
//             +"xYOmAOEZPFTh7/gKcVwKLikSLw+K2Z7j70yVU5AS3CmJofnidvEEtlfqb9nQQROo"
//             +"T2EmbTYvxyC+nr9PTxq0n00BrISQ3lMVKB2aHdgLAZrRyQeU7WXM3eOCFRPEudgQ"
//             +"c68FdVpjVKkMRSUtSLpYqzKSWocr6vp89r1fWxjrzjtU9NBfw5ELXcsTN1msZJHf"
//             +"3jvcdMGFHpLPJMRPjsCAc/LZD4Uwi83sN65fl0pe1BSW8CMnspVAkhe4UTM28dB9"
//             +"TOMmP4s7YwdfvspsaDpi3PToKexZLZ/pgoFjcGAFDbOqMTY43WMMtRyKRr7aKETO"
//             +"l9cUYtj3AgMBAAECggEBAIbNQium3lDUijMRh/TGJrXRSkzO3KoxhbmtvqUJCBtI"
//             +"mBGgwZ33yrCO2MaGg/stL3kIOBzPU6cJFSUjOkbWYtfokT/vh+yLku4EwoWI7EyQ"
//             +"DliQ7WLXgmja/QSO2/ImB83v9jJuDqRgBn2+/OMkccrwgK1n8NMWw7vIrHrVWiJk"
//             +"xDiNGa1GmFljgWnHH4+Wof+v0tnTPYn5MOiczQuCir+QrfLc10C7n5BmGDzheMCL"
//             +"MC0S6cMjIxiR/hFgZuDHiFfEmWKq1acsd605lrWRK+v9VJSPpCPRP0H2l0jYHFpl"
//             +"IRA4Iu7hW3kgvOmiJmVU3Cf3pG1pCK+fH0yxtDkPt6ECgYEAwaUSGD7AX5Q6VSdr"
//             +"5SgPfS5cMCLBjgu6hobPgWxFzuFp6qCuOgiIVwPM246gN0xd6T9JKE4mKYKijXmZ"
//             +"Np0ly+R0jiSrAwzpVWAI+F0IGZxIU3svL8z0jFXZSz8r6gG8SzV8lBXi8OV5bRHg"
//             +"hLYQt+R6D5jGvEuKd2zSeNDglfkCgYEAs3/Dhhc/RdF/4qG9utYq0ESV8sAGyHOe"
//             +"nXuMV2YKvejKD/d2xpgwjI0BdI6w6LRkN7EVDfjnLVtuCZF5rBUGm+VYisCKYsz9"
//             +"ii059JACiP7bPtG6zz6afDhRUPq+tOzOEYFNm8DQwl/wOV2n76don/7pZKFvjkBu"
//             +"c4b8sOp84m8CgYEAvGZvzmrvG47JmiO6k7+AIljClIqcKik7Frt+k/rViExDkmU2"
//             +"XXwDujUWUN7Y/jQsgkxyTuaJtoVExcRyznHiXhctV0ZRo6wiMFA5KfrJcLFepOoK"
//             +"pMURgJ/dw5n4jbmWis3FIQaSP7Hji7yC5luEtIV0RExtvrD4TOzxcV43w3ECgYEA"
//             +"r0BEs/yqiA49YBYuWeaUMndkN3gIp1lLOdLQeNxmDHjmH6Sq0MbyT6e0Dgrq6qiF"
//             +"WGKKffPQMdacnrbsJnj41OidBAtskX425Nu3Q/H+p6a8hJ7cV092IWYS7o+B9r9l"
//             +"im3GShV9POnSbw/j0PaQDfYiBWAgvLBnpl/bAxhOCf0CgYAZEZNmkZLaIa324B9D"
//             +"3hqDxfQnw6+3l56D2NSMeRBSAoPPR/NOQ6OaDW+DvVV2rywkVSv/DStr84Ssl0g4"
//             +"wCD9WyiiAS8kq6BM99xkZNyIWdSUN1t2Dr78vmCUOD/S0S8L89UhcVHqdmbTe4CC"
//             +"2FE56KZfaculguLg4enTKEdJyQ=="
//             +"-----END PRIVATE KEY-----

public class Junk {

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


    public static boolean keyGen() throws NoSuchAlgorithmException, IOException, OperatorCreationException, InvalidKeySpecException {
        try{
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");  
            kpGen.initialize(2048, new SecureRandom());  
            KeyPair keyPair = kpGen.generateKeyPair();
        
            //unencrypted private key form of PKCS#8  
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
            PemObject pemObject = new PemObject("PUBLIC KEY", pubBytes);
            StringWriter stringWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(stringWriter);
            pemWriter.writeObject(pemObject);
            pemWriter.close();
            String pemString = stringWriter.toString();
            FileOutputStream fos2 = new FileOutputStream("pubk.key");  
            fos2.write(pemString.getBytes());  
            fos2.flush();  
            fos2.close();

            return true;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
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
    
    private static void save(KeyPair keyPair, String publicKeyOutput, String privateKeyOutput) throws IOException {
        // final PrivateKey privateKey = keyPair.getPrivate();
        // final PublicKey publicKey = keyPair.getPublic();

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

}