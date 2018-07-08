package votingelectionbooth;



import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import static votingelectionbooth.CLA_Agency.load_private_key;
import static votingelectionbooth.CLA_Agency.load_public_key;

public class Election_voter {

    private String name;
    private int tally = 0;
    private String code;
    private int id;
    private double validation;
    private String password;

    public static final String APrv_kf = "src/Aprv.key";
    public static final String APub_kf = "src/Apub.key";
    public static final String BPrv_kf = "src/Bprv.key";
    public static final String BPub_kf = "src/Bpub.key";

    static byte[] byte_key;
    static String str_key;
    static Cipher des_enc_cipher;
    static Cipher des_dec_cipher;
    SecretKey usekey;
    static String in_code;
    static String in_validation;
    static String in_id;

    public Election_voter(String name, String pass, int id) {
        this.name = name;
        password = pass;
        this.id = id;
    }

    public void setcode(String vote) {
        code = vote;
    }

    public String getcode() {
        return code;
    }

    public String getName() {
        return name;
    }

    public String getPassword() {
        return password;
    }

    public void setvalidation(double val) {
        if (tally == 0) {
            validation = val;
            tally = 1;
        }
    }

    public double getvalidation() {
        return validation;
    }

    public int gettally() {
        return tally;
    }

    

    public static String generate_TimeStamp() {
        LocalDateTime currentTime = LocalDateTime.now();
        System.out.println("Current DateTime: " + currentTime);
        int months = currentTime.getMonthValue();
        int day = currentTime.getDayOfMonth();
        int hours = currentTime.getHour();
        int minutes = currentTime.getMinute();
        int seconds = currentTime.getSecond();
        int msec = currentTime.getNano();
        return (months + "" + day + "" + hours + "" + minutes + "" + seconds + "" + msec);
    }

  

    public static void main(String[] args) throws ClassNotFoundException, NoSuchAlgorithmException, Exception {
        /**
         * ******************RUN CTF AND CLA FILES FIRST*******************
         */
        System.out.println("Election_voter CLASS");
        System.out.println("Check If CTF AND CLA IS UP AND RUNNING");
        SecretKey key = KeyGenerator.getInstance("DES").generateKey();
        byte_key = key.getEncoded();
        str_key = new sun.misc.BASE64Encoder().encode(byte_key);
        
        Scanner voter_inp = new Scanner(System.in);

        System.out.println("Default Link IP: 127.0.0.1)\nPlease enter desired "
                + "Link IP or Hit Enter to proceed with loopback interface IP");
        String serverName = "127.0.0.1";
        if (voter_inp.nextLine().trim().length() > 0) {
            serverName = voter_inp.nextLine();
        }

        Random rand = new Random();
        int noun1 = rand.nextInt(15000) + 1;

        //Connect to CLA
        int port_num1 = 7860;
        String initiator_id = "VOTER";
        String name_enc1 = null;
        
            System.out.println("Connecting to " + serverName
                    + " on port: " + port_num1 + " with CLA");
            Socket client = new Socket(serverName, port_num1);

            System.out.println("Connection Established with: "
                    + client.getRemoteSocketAddress() + "\n");

            final PublicKey respublicKey = load_public_key(BPub_kf);
            final PrivateKey intiprivateKey = load_private_key(APrv_kf);

            DataOutputStream out = new DataOutputStream(client.getOutputStream());
            DataInputStream inp = new DataInputStream(client.getInputStream());

            //Sending NOUNCE1 and ID To CLA
            System.out.println("NOUNCE1 AND INITIATOR ID -------> CLA");
            String msg_sent1 = (noun1 + "," + initiator_id + "," + generate_TimeStamp());
            final byte[] cipher_txt = JEncrypRSA.encoded(msg_sent1, respublicKey);
            System.out.println("1. Message Sent (Original): " + msg_sent1);
            out.writeUTF(new sun.misc.BASE64Encoder().encode(cipher_txt));
            System.out.println("1.1 Encrypted Sent Message:\n"
                    + new sun.misc.BASE64Encoder().encode(cipher_txt) + "\n");

            //Recieving NOUNCE1 and NOUNCE2 From CLA 
            System.out.println("CLA -------> NOUNCE1 AND NOUNCE2");
            String msg1 = inp.readUTF();
            byte[] msg1byte = new sun.misc.BASE64Decoder().decodeBuffer(msg1);
            final String rec_msg1 = JEncrypRSA.decoded(msg1byte, intiprivateKey);
            System.out.println("2. Decrypted Recieved Message: " + rec_msg1
                    + "\n2.1 Encrypted Recieved MEssage: \n" + msg1 + "\n");

            String temp = rec_msg1.substring(rec_msg1.indexOf(',') + 1);
            String nounce2 = temp.substring(0, temp.indexOf(','));

            //Sending NOUNCE2 to CLA
            System.out.println("NOUNCE2-------> CLA TO VALIDATE");
            String msg_sent2 = (nounce2 + "," + generate_TimeStamp());
            final byte[] cipher_txt2 = JEncrypRSA.encoded(msg_sent2, respublicKey);
            System.out.println("3. Message(Original): " + msg_sent2);
            out.writeUTF(new sun.misc.BASE64Encoder().encode(cipher_txt2));
            System.out.println("3.1 Encrypted Sent Message:\n"
                    + new sun.misc.BASE64Encoder().encode(cipher_txt2) + "\n");

            //Sending Session key to CLA
            System.out.println("SESSION KEY ------> CLA");
            String session_key = (str_key + "," + generate_TimeStamp());
            final byte[] session_key_ciphertxt = JEncrypRSA.encoded(session_key, respublicKey);
            System.out.println("4. Message Sent: " + session_key + "\n4.1 "
                    + "Encrypted Sent Message:\n"
                    + new sun.misc.BASE64Encoder().encode(session_key_ciphertxt) + "\n");
            out.writeUTF(new sun.misc.BASE64Encoder().encode(session_key_ciphertxt));

        }
    }


