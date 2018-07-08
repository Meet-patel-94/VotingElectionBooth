package votingelectionbooth;

import javax.crypto.Cipher;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.util.Scanner;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;


public class JEncrypRSA {
    public static String APRK_PATH = "src/lab3Keys/Aprv.key";
    public static String APBK_PATH = "src/lab3Keys/Apub.key";
    
    //Decoding method which generates cipher to be used for decryption using private key. Result is converted to String to retrieve plain text and is returned. Possible Exceptions thrown include NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, etc., and so general Exception being thrown is used.
    public static String decoded(byte[] cipher_txt, PrivateKey keyPRIV)throws Exception {
        Cipher decCiph = Cipher.getInstance("RSA");
        decCiph.init(Cipher.DECRYPT_MODE, keyPRIV);
        String plain = new String(decCiph.doFinal(cipher_txt));
        return plain;
    }
    
    //Encoding method which generates cipher to be used for encryption using public key. Result is byte encrypted and is returned. Possible Exceptions thrown include NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, etc., and so general Exception being thrown is used.
    public static byte[] encoded(String inputMsg, PublicKey keyPUBL) throws Exception {
        Cipher encCiph = Cipher.getInstance("RSA");
        encCiph.init(Cipher.ENCRYPT_MODE, keyPUBL);
        byte[] byteEnc = encCiph.doFinal(inputMsg.getBytes());
        return byteEnc;
    }
    
    //Method used to generate Public and Private Keys after generating pair and initializing to 2048. Parent Directory is checked for and created if it does not already exist. New Private Key File is created and written to using Class ObjectOutputStream, and process is repeated for Public Key File. 
    public static void keyGeneration() throws Exception {
        KeyPairGenerator keyPGen = KeyPairGenerator.getInstance("RSA");
        keyPGen.initialize(2048);
        KeyPair kPair = keyPGen.generateKeyPair();
        File keyPriv = new File(APRK_PATH);
        File keyPub = new File(APBK_PATH);
        
        if (keyPriv.getParentFile() != null) {
            keyPriv.getParentFile().mkdirs();
        }
        if (keyPub.getParentFile() != null) {
            keyPub.getParentFile().mkdirs();
        }
        
        keyPriv.createNewFile();
        ObjectOutputStream keyPrivFile = new ObjectOutputStream(new FileOutputStream(keyPriv));
        keyPrivFile.writeObject(kPair.getPrivate());
        keyPrivFile.close();
        
        keyPub.createNewFile();
        ObjectOutputStream keyPubFile = new ObjectOutputStream(new FileOutputStream(keyPub));
        keyPubFile.writeObject(kPair.getPublic());
        keyPubFile.close();
    }
    
    public static void main (String[] argv) throws Exception {
        String msg, txtDecrypted;
        byte[] txtEncrypted;
        Scanner inp = new Scanner(System.in);
        System.out.println("RSA ALGORITHM ENCRYPTION\n\nPLEASE ENTER THE FOLLOWING TO BE ENCRYPTED:\n(\"No body can see me\")");
        msg = inp.nextLine();
        System.out.println("MESSAGE ENTERED:\n" + msg);
        System.out.println("GENERATING PUBLIC AND PRIVATE KEYS\n");
        
        File fPrivKey = new File(APRK_PATH);
        File fPubKey = new File(APBK_PATH);
        
        if (!(fPrivKey.exists() && fPubKey.exists())) {
            keyGeneration();
        }
        
        System.out.println("KEYS GENERATED SUCCESSFULLY\nENCODING MESSAGE USING PUBLIC KEY\n");
        
        ObjectInputStream inStream = new ObjectInputStream(new FileInputStream(APBK_PATH));
        PublicKey publ = (PublicKey)inStream.readObject();
        txtEncrypted = encoded(msg, publ);
        System.out.println("ENCODED MESSAGE:\n" + txtEncrypted);
        System.out.println("DECODING MESSAGE USING PRIVATE KEY\n");
        
        ObjectInputStream inStreamPriv = new ObjectInputStream(new FileInputStream(APRK_PATH));
        PrivateKey priv = (PrivateKey)inStreamPriv.readObject();
        txtDecrypted = decoded(txtEncrypted, priv);
        System.out.println("DECODED MESSAGE:\n" + txtDecrypted);
    }
}