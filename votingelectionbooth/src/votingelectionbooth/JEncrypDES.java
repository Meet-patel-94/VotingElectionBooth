package votingelectionbooth;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import java.util.Scanner;



public class JEncrypDES {
    
    //Decoding method which generates cipher to be used for decryption. Cipher is used in order to decrypt based on Base64 Decoding. Result is converted to String to retrieve plain text and is returned. Possible Exceptions thrown include NoSuchAlgorithmException, InvalidKeyException,IOException, etc., and so general Exception being thrown is used.
    public static String decoded(String cipher_txt, SecretKey keyDES) throws Exception{
        Cipher decCiph = Cipher.getInstance("DES");
        decCiph.init(Cipher.DECRYPT_MODE, keyDES);
        byte[] byteDec = decCiph.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(cipher_txt));
        String plain = new String(byteDec, "UTF8");
        return plain;
    }
    
    //Encoding method which generates cipher to be used for encryption.Plain text message is converted from String to encrypted byte, which is then encoded based on Base64 Encoding. Possible Exceptions thrown include NoSuchAlgorithmException, InvalidKeyException,IOException, etc., and so general Exception being thrown is used.
    public static String encoded(String inputMsg, SecretKey keyDES) throws Exception {
        Cipher encCiph = Cipher.getInstance("DES");
        encCiph.init(Cipher.ENCRYPT_MODE, keyDES);
        byte[] byteEnc = encCiph.doFinal(inputMsg.getBytes("UTF8"));
        String encodedMsg = new sun.misc.BASE64Encoder().encode(byteEnc);
        return encodedMsg;
    }
    
    public static void main (String[] argv) throws Exception {
        String msg, txtEncrypted, txtDecrypted;
        Scanner inp = new Scanner(System.in);
        System.out.println("DES ALGORITHM ENCRYPTION\n\nPLEASE ENTER THE FOLLOWING TO BE ENCRYPTED:\n(\"No body can see me\")");
        msg = inp.nextLine();
        System.out.println("MESSAGE ENTERED:\n" + msg);
        System.out.println("GENERATING DES KEY\n");
        SecretKey keyDES = KeyGenerator.getInstance("DES").generateKey();
        System.out.println("KEY GENERATED SUCCESSFULLY\nENCODING MESSAGE USING PUBLIC KEY\n");
        txtEncrypted = encoded(msg, keyDES);
        System.out.println("ENCODED MESSAGE:\n" + txtEncrypted);
        System.out.println("DECODING MESSAGE USING PRIVATE KEY\n");
        txtDecrypted = decoded(txtEncrypted, keyDES);
        System.out.println("DECODED MESSAGE:\n" + txtDecrypted);
    }
}
