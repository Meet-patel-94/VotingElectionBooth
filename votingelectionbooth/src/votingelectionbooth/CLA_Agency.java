/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package votingelectionbooth;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.LocalDateTime;
import java.util.Random;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CLA_Agency extends Thread {

  
    private static double validation;
    private static String code = "sa2F5hjI9";
    private static int curID;

    public static final String APrv_kf = "src/Aprv.key";
    public static final String APub_kf = "src/Apub.key";
    public static final String BPrv_kf = "src/Bprv.key";
    public static final String BPub_kf = "src/Bpub.key";

    static Cipher des_enc_cipher;
    static Cipher des_dec_cipher;
    SecretKey usekey;

    //For DES encryption and decryption
    static byte[] byte_key;
    static String str_key;


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

   

    static PublicKey load_public_key(String file_name) throws IOException {
        ObjectInputStream oin
                = new ObjectInputStream(new BufferedInputStream(
                        new FileInputStream(file_name)));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PublicKey pubKey = fact.generatePublic(keySpec);
            return pubKey;
        } catch (Exception e) {
            throw new RuntimeException("serialisation error", e);
        } finally {
            oin.close();
        }
    }

    static PrivateKey load_private_key(String file_name) throws IOException {
        ObjectInputStream oin
                = new ObjectInputStream(new BufferedInputStream(
                        new FileInputStream(file_name)));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PrivateKey privKey = fact.generatePrivate(keySpec);
            return privKey;
        } catch (Exception e) {
            throw new RuntimeException("serialisation error", e);
        } finally {
            oin.close();
        }
    }
//****************CONN START ******************//
    private ServerSocket server_socket;

    public CLA_Agency(int port) throws IOException {
        server_socket = new ServerSocket(port);
    }

    public void run() {
        while (true) {
            try {
                int noun1;
                Random rand = new Random();
                int noun2 = rand.nextInt(15000) + 1;
                validation = noun2;

                Socket server = server_socket.accept();
                if (server.getRemoteSocketAddress() != null) {
                    System.out.println("Connection Established with: "
                            + server.getRemoteSocketAddress() + "\n");
                } else {
                    System.out.println("Connection Established with: 127.0.0.1\n");
                }

                int port_num1 = server_socket.getLocalPort();
                if (port_num1 == 7860) {
                    System.out.println("Conneted on Port: " + port_num1 + " with Election_voter");
                    DataInputStream inp = new DataInputStream(server.getInputStream());
                    DataOutputStream out = new DataOutputStream(server.getOutputStream());

                    final PublicKey intipublicKey = load_public_key(APub_kf);
                    final PublicKey respublicKey = load_public_key(BPub_kf);
                    final PrivateKey resprivateKey = load_private_key(BPrv_kf);

                    //Receiving NOUNCE1 and ID from Election_voter 
                    System.out.println("Elecction_voter------->NOUNCE1 AND INITIATOR ID");
                    String msg1 = inp.readUTF();
                    byte[] msg1byte = new sun.misc.BASE64Decoder().decodeBuffer(msg1);
                    final String rec_msg1 = JEncrypRSA.decoded(msg1byte, resprivateKey);
                    System.out.println("1. Decrypted Recieved Message: " + rec_msg1
                            + "\n1.1 Encrypted Recieved Message: \n" + msg1 + "\n");

                    String nounce = rec_msg1.substring(0, rec_msg1.indexOf(','));
                    String temp = rec_msg1.substring(rec_msg1.indexOf(',') + 1);
                    String sender_id = temp.substring(temp.indexOf(',') + 1);
                    String time1 = temp.substring(temp.indexOf(',') + 1);

                    double times1 = Double.parseDouble(time1);

                    //Sending NOUNCE1 and NOUNCE2 to Election_voter 
                    System.out.println("NOUNCE1 AND NOUNCE2------>Election_voter");
                    String msg_sent1 = (nounce + "," + noun2 + "," + generate_TimeStamp());
                    final byte[] cipher_txt = JEncrypRSA.encoded(msg_sent1, intipublicKey);
                    System.out.println("2. Message Sent (Original): " + msg_sent1);
                    out.writeUTF(new sun.misc.BASE64Encoder().encode(cipher_txt));
                    System.out.println("2.1 Encrypted Sent message:\n"
                            + new sun.misc.BASE64Encoder().encode(cipher_txt) + "\n");

                    //Receiving NOUNCE2 from Election_voter 
                    System.out.println("Election_voter------>NOUNCE2");
                    String msg2 = inp.readUTF();
                    byte[] msg2byte = new sun.misc.BASE64Decoder().decodeBuffer(msg2);
                    final String rec_msg2 = JEncrypRSA.decoded(msg2byte, resprivateKey);
                    String nounce2 = noun2 + "";
                    String nounce2check = rec_msg2.substring(0, rec_msg2.indexOf(','));
                    String temp3 = rec_msg2.substring(rec_msg2.indexOf(',') + 1);

                    double times3 = Double.parseDouble(temp3);
                    if (times3 < times1) {
                        break;
                    }
                    System.out.println("Timestamp after receiving msg2: " + times3
                            + "\n3. Decrypted Recieved Message: " + rec_msg2
                            + "\n3.1 Encrypted Recieved message: \n" + msg2 + "\n");

                    //Recieving E(Pr Ks) From Election_voter 
                    String msg3 = inp.readUTF();
                    byte[] msg3byte = new sun.misc.BASE64Decoder().decodeBuffer(msg3);
                    final String rec_msg3 = JEncrypRSA.decoded(msg3byte, resprivateKey);
                    System.out.println("4. Decrypted Recieved Message: " + rec_msg3
                            + "\n4.1 Encrypted Recieved Message: \n" + msg3 + "\n");

                    String keys = rec_msg3.substring(0, rec_msg3.indexOf(','));
                    String temp4 = rec_msg3.substring(rec_msg3.indexOf(',') + 1);

                    double times4 = Double.parseDouble(temp4);

                    if (times4 < times3) {
                        break;
                    }
                    System.out.println("Timestamp after receiving msg3: " + times4);

                    byte[] des_keys = new sun.misc.BASE64Decoder().decodeBuffer(keys);
                    usekey = new SecretKeySpec(des_keys, 0, des_keys.length, "DES");
//
//                    cipher_DESEncryption(usekey);
//                    cipher_DESDecryption(usekey);
                    Scanner voter_inp = new Scanner(System.in);

                    String incoming1 = inp.readUTF();
                    System.out.println("---->name: " +  JEncrypDES.decoded(incoming1,usekey));
                    String voter_name =  JEncrypDES.decoded(incoming1,usekey);

                    String incoming2 = inp.readUTF();
                    System.out.println("---->password: " +  JEncrypDES.decoded(incoming2,usekey));
                    String voter_pass =  JEncrypDES.decoded(incoming2,usekey);

                  
                    
                }
            } catch (SocketTimeoutException s) {
                System.out.println("Timed Out for Soctet!");
                break;
            } catch (IOException e) {
                e.printStackTrace();
                break;
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(CLA_Agency.class.getName()).log(Level.SEVERE, null, ex);
            } catch (Exception ex) {
                Logger.getLogger(CLA_Agency.class.getName()).log(Level.SEVERE, null, ex);
            }

        }
    }

    public static void main(String[] args) throws ClassNotFoundException, NoSuchAlgorithmException, Exception {
        /**
         * ******************RUN CTF FILE FIRST*******************
         */
        System.out.println("Check IF CTF IS UP AND RUNNING");
        Random rand = new Random();
        
        int port_num1 = 7860;
        try {
            Thread t = new CLA_Agency(port_num1);
            t.start();
        } catch (IOException e) {
            e.printStackTrace();
        }

        //Connection with CTF to send valication code
        int port_num2 = 7861;
        int noun1 = rand.nextInt(15000) + 1;
        String initiator_id = "CLA";
        SecretKey key = KeyGenerator.getInstance("DES").generateKey();
        byte_key = key.getEncoded();
        str_key = new sun.misc.BASE64Encoder().encode(byte_key);
//        cipher_DESEncryption(key);
//        cipher_DESDecryption(key);
        String server_name = null;
        try {
            if (server_name == null) {
                System.out.println("Connecting to localhost on port: "
                        + port_num2 + " with CTF");
            } else {
                System.out.println("Connecting to " + server_name
                        + " on port " + port_num2);
            }
            Socket client_conn = new Socket(server_name, port_num2);
            System.out.println("Connection Established with: "
                    + client_conn.getRemoteSocketAddress() + "\n");

            System.out.println("Validation#: " + validation);
            System.out.println("Code: " + code);
            System.out.println("ID: " + curID + "\n");

            final PublicKey respublicKey = load_public_key(BPub_kf);
            final PublicKey intipublicKey = load_public_key(APub_kf);
            final PrivateKey intiprivateKey = load_private_key(APrv_kf);
            
            DataOutputStream out = new DataOutputStream(client_conn.getOutputStream());
            DataInputStream inp = new DataInputStream(client_conn.getInputStream());

            //Sending NOUNCE1 and ID To CTF
            System.out.println("NOUNCE1 AND INITIATOR ID------->CTF");
            String msg_sent1 = (noun1 + "," + initiator_id + "," + generate_TimeStamp());
            final byte[] cipher_txt = JEncrypRSA.encoded(msg_sent1, respublicKey);
            System.out.println("1. Message Sent (Original): " + msg_sent1);
            out.writeUTF(new sun.misc.BASE64Encoder().encode(cipher_txt));
            System.out.println("1.1 Encrypted Sent Message:\n"
                    + new sun.misc.BASE64Encoder().encode(cipher_txt) + "\n");

            //Recieving NOUNCE1 and NOUNCE2 From CTF 
            System.out.println("CTF------->NOUNCE1 AND NOUNCE2");
            String msg1 = inp.readUTF();
            byte[] msg1byte = new sun.misc.BASE64Decoder().decodeBuffer(msg1);
            final String rec_msg1 = JEncrypRSA.decoded(msg1byte, intiprivateKey);
            System.out.println("2. Decrypted Recieved Message: " + rec_msg1
                    + "\n2.1 Encrypted Recieved Message: \n" + msg1 + "\n");
            String temp = rec_msg1.substring(rec_msg1.indexOf(',') + 1);
            String nounce2 = temp.substring(0, temp.indexOf(','));

            //Sending NOUNCE2 to CTF
            System.out.println("NOUNCE2 -----> CTF To Validate");
            String msg_sent2 = (nounce2 + "," + generate_TimeStamp());
            final byte[] cipher_txt2 = JEncrypRSA.encoded(msg_sent2, respublicKey);
            System.out.println("3. Message Sent (Original): " + msg_sent2);
            out.writeUTF(new sun.misc.BASE64Encoder().encode(cipher_txt2));
            System.out.println("3.1 Encrypted Sent Message:\n"
                    + new sun.misc.BASE64Encoder().encode(cipher_txt2) + "\n");

            //Sending Session key to CTF
            System.out.println("SESSION KEY ------> CTF");
            String session_key = (str_key + "," + generate_TimeStamp());
            final byte[] session_key_ciphertxt = JEncrypRSA.encoded(session_key, respublicKey);
            System.out.println("4. Message: " + session_key + "\n4.1 "
                    + "Encrypted Sent Message:\n"
                    + new sun.misc.BASE64Encoder().encode(session_key_ciphertxt) + "\n");
            out.writeUTF(new sun.misc.BASE64Encoder().encode(session_key_ciphertxt));

            String valid_enc3 =  JEncrypDES.encoded("" + validation,key);
            System.out.println("Encrypted Validation#: " + valid_enc3);
            out.writeUTF(valid_enc3);

            String code_enc1 =  JEncrypDES.encoded(code,key);
            System.out.println("Encrypted Code: " + code_enc1);
            out.writeUTF(code_enc1);

            String id_enc2 =  JEncrypDES.encoded("" + curID,key);
            System.out.println("Encrypted ID: " + id_enc2);
            out.writeUTF(id_enc2);

            client_conn.close();
            System.out.println("\nStart Election_voter LINK WITH THIS INSTANCE OF CLA");
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
