/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package votingelectionbooth;



import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import static votingelectionbooth.CLA_Agency.load_private_key;
import static votingelectionbooth.CLA_Agency.load_public_key;
import static votingelectionbooth.Election_voter.in_validation;

public class CTF_Facility extends Thread {

    private int tally = 0;
  
    private String validation;
    private String code;
    private String userid;

   public static final String APrv_kf = "src/Aprv.key";
    public static final String APub_kf = "src/Apub.key";
    public static final String BPrv_kf = "src/Bprv.key";
    public static final String BPub_kf = "src/Bpub.key";

    static Cipher DESEncryption_cipher;
    static Cipher DESDecryption_cipher;
    SecretKey key_CLA;
    SecretKey key_Election_voter;



    public static String generate_TimeStamp() {
        LocalDateTime currentTime = LocalDateTime.now();
        System.out.println("Current Timestamp: " + currentTime);
        int months = currentTime.getMonthValue();
        int day = currentTime.getDayOfMonth();
        int hours = currentTime.getHour();
        int minutes = currentTime.getMinute();
        int seconds = currentTime.getSecond();
        int msec = currentTime.getNano();
        return (months + "" + day + "" + hours + "" + minutes + "" + seconds + "" + msec);
    }

 
//****************CONN START ******************//
    private ServerSocket server_socket;

    public CTF_Facility(int port) throws IOException {
        server_socket = new ServerSocket(port);
    }

    public void run() {

        while (true) {
            try {
                Random rand = new Random();
                int noun2 = rand.nextInt(15000) + 1;

                Socket server = server_socket.accept();
                if (server.getRemoteSocketAddress() != null) {
                    System.out.println("Connection Established with: "
                            + server.getRemoteSocketAddress() + "\n");
                } else {
                    System.out.println("Connection Established with: 127.0.0.1\n");
                }
                int port_num = server_socket.getLocalPort();

                if (port_num == 7861) {
                    System.out.println("Conneted on Port: " + port_num + " with CLA");
                    DataInputStream inp = new DataInputStream(server.getInputStream());
                    DataOutputStream out = new DataOutputStream(server.getOutputStream());

                    final PublicKey intipublicKey = load_public_key(APub_kf);
                    final PrivateKey resprivateKey = load_private_key(BPrv_kf);

                    //Receiving NOUNCE1 and ID From CLA 
                    System.out.println("CLA --------> NOUNCE1 AND INITIATOR ID");
                    String msg1 = inp.readUTF();
                    byte[] msg1byte = new sun.misc.BASE64Decoder().decodeBuffer(msg1);
                    final String rec_msg1 = JEncrypRSA.decoded(msg1byte, resprivateKey);
                    System.out.println("1. Decrypted Recieved message: " + rec_msg1
                            + "\n1.1 Encrypted Recieved message: \n" + msg1 + "\n");

                    String nounce = rec_msg1.substring(0, rec_msg1.indexOf(','));
                    String temp = rec_msg1.substring(rec_msg1.indexOf(',') + 1);
                    String time1 = temp.substring(temp.indexOf(',') + 1);

                    double times1 = Double.parseDouble(time1);

                    //Sending NOUNCE1 and NOUNCE2 to CLA 
                    System.out.println("NOUNCE1 AND NOUNCE2 ---------> CLA");
                    String msg_sent1 = (nounce + "," + noun2 + "," + generate_TimeStamp());
                    final byte[] cipher_txt = JEncrypRSA.encoded(msg_sent1, intipublicKey);
                    System.out.println("2. Message Sent : " + msg_sent1);
                    out.writeUTF(new sun.misc.BASE64Encoder().encode(cipher_txt));
                    System.out.println("2.1 Encrypted Sent Message:\n"
                            + new sun.misc.BASE64Encoder().encode(cipher_txt) + "\n");

                    //Recieving NOUNCE2 from CLA  
                    System.out.println("CLA-------->NOUNCE2");
                    String msg2 = inp.readUTF();
                    byte[] msg2byte = new sun.misc.BASE64Decoder().decodeBuffer(msg2);
                    final String rec_msg2 = JEncrypRSA.decoded(msg2byte, resprivateKey);
                    String temp3 = rec_msg2.substring(rec_msg2.indexOf(',') + 1);

                    double times3 = Double.parseDouble(temp3);
                    if (times3 < times1) {
                        break;
                    }
                    System.out.println("Timestamp after receiving msg2: " + times3
                            + "\n3. Decrypted Recieved message: " + rec_msg2
                            + "\n3.1 Encrypted recieved message: \n" + msg2 + "\n");

                    //Recieving E(Pr Ks) From CLA 
                    String msg3 = inp.readUTF();
                    byte[] msg3byte = new sun.misc.BASE64Decoder().decodeBuffer(msg3);
                    final String rec_msg3 = JEncrypRSA.decoded(msg3byte, resprivateKey);
                    System.out.println("4. Decrypted Recieved message: " + rec_msg3
                            + "\n4.1 Encrypted Recieved message: \n" + msg3 + "\n");

                    String keys = rec_msg3.substring(0, rec_msg3.indexOf(','));
                    String temp4 = rec_msg3.substring(rec_msg3.indexOf(',') + 1);

                    double times4 = Double.parseDouble(temp4);
                    if (times4 < times3) {
                        break;
                    }
                    System.out.println("Timestamp after receiving msg3: " + times4);

                    byte[] des_keys = new sun.misc.BASE64Decoder().decodeBuffer(keys);
                    key_CLA = new SecretKeySpec(des_keys, 0, des_keys.length, "DES");

                 //    cipher_DESEncryption(key_CLA);////////////////////
                //     cipher_DESDecryption(key_CLA);///////////////////

                    String incoming1 = inp.readUTF();
                    validation = JEncrypDES.decoded(incoming1,key_CLA);
                    System.out.println("Incoming 1 ******** Validation: " + validation);
                    String incoming2 = inp.readUTF();
                    code = JEncrypDES.decoded(incoming2,key_CLA);/////////////////
                    System.out.println("Incoming 2 ********** code: " + code);
                    String incoming3 = inp.readUTF();
                    userid = JEncrypDES.decoded(incoming3,key_CLA);/////////////////
                    System.out.println("Incoming 3 ******* UserID: " + userid);

                    server.close();
                    System.out.println("\nStart Election_voter");
                    break;
                } else if (port_num == 7862) {
                    System.out.println("Conneted on Port: " + port_num + " with voter.");
                    DataInputStream inp = new DataInputStream(server.getInputStream());
                    DataOutputStream out = new DataOutputStream(server.getOutputStream());

                    final PublicKey intipublicKey = load_public_key(APub_kf);
                    final PrivateKey resprivateKey = load_private_key(BPrv_kf);

                    //Receiving NOUNCE1 and ID from Voter 
                    System.out.println("Election_voter --------> NOUNCE1 AND INITIATOR ID");
                    String msg1 = inp.readUTF();
                    byte[] msg1byte = new sun.misc.BASE64Decoder().decodeBuffer(msg1);
                    final String rec_msg1 = JEncrypRSA.decoded(msg1byte, resprivateKey);
                    System.out.println("1. Decrypted Recieved message: " + rec_msg1
                            + "\n1.1 Encrypted Recieved message: \n" + msg1 + "\n");

                    String nounce = rec_msg1.substring(0, rec_msg1.indexOf(','));
                    String temp = rec_msg1.substring(rec_msg1.indexOf(',') + 1);
                    String time1 = temp.substring(temp.indexOf(',') + 1);

                    double times1 = Double.parseDouble(time1);

                    //Sending NOUNCE1 and NOUNCE2 to Voter 
                    System.out.println("NOUNCE1 AND NOUNCE2-------->Election_voter");
                    String msg_sent1 = (nounce + "," + noun2 + "," + generate_TimeStamp());
                    final byte[] cipher_txt = JEncrypRSA.encoded(msg_sent1, intipublicKey);
                    System.out.println("2. Message Sent (Original): " + msg_sent1);
                    out.writeUTF(new sun.misc.BASE64Encoder().encode(cipher_txt));
                    System.out.println("2.1 Encrypted Sent Message:\n"
                            + new sun.misc.BASE64Encoder().encode(cipher_txt) + "\n");

                    //Receiving NOUNCE2 from Voter 
                    System.out.println("Election_voter--------->RECEIVING NOUNCE2");
                    String msg2 = inp.readUTF();
                    byte[] msg2byte = new sun.misc.BASE64Decoder().decodeBuffer(msg2);
                    final String rec_msg2 = JEncrypRSA.decoded(msg2byte, resprivateKey);
                    String temp3 = rec_msg2.substring(rec_msg2.indexOf(',') + 1);

                    double times3 = Double.parseDouble(temp3);
                    if (times3 < times1) {
                        break;
                    }
                    System.out.println("Timestamp after receiving msg2: " + times3
                            + "\n3. Decrypted Recieved Messahe: " + rec_msg2
                            + "\n3.1 Encrypted Recieved Message: \n" + msg2 + "\n");

                    //Recieving E(Pr Ks) From Voter 
                    String msg3 = inp.readUTF();
                    byte[] msg3byte = new sun.misc.BASE64Decoder().decodeBuffer(msg3);
                    final String rec_msg3 = JEncrypRSA.decoded(msg3byte, resprivateKey);
                    System.out.println("4. Message Received(Decrypted): " + rec_msg3
                            + "\n4.1 Message Received (Encrypted): \n" + msg3 + "\n");

                    String keys = rec_msg3.substring(0, rec_msg3.indexOf(','));
                    String temp4 = rec_msg3.substring(rec_msg3.indexOf(',') + 1);

                    double times4 = Double.parseDouble(temp4);

                    if (times4 < times3) {
                        break;
                    }
                    System.out.println("Timestamp after receiving msg3: " + times4);

                    byte[] des_keys = new sun.misc.BASE64Decoder().decodeBuffer(keys);
                    key_Election_voter = new SecretKeySpec(des_keys, 0, des_keys.length, "DES");

//                    cipher_DESEncryption(key_Election_voter);////////////
//                    cipher_DESDecryption(key_Election_voter);//////////

                    String incoming1 = inp.readUTF();
                    String checkval = JEncrypDES.decoded(incoming1,key_Election_voter);///////////
                    System.out.println("Received Voter *********Validation#: " + checkval);
                    String incoming2 = inp.readUTF();
                    String checkid = JEncrypDES.decoded(incoming2,key_Election_voter);///////////
                    System.out.println("Received **********Voter ID: " + checkid);
                    String incoming3 = inp.readUTF();
                    String checkcode = JEncrypDES.decoded(incoming3,key_Election_voter);
                    System.out.println("Received ********Voter Code: " + checkcode + "\n");
                    Boolean vote_add = false;


                

                    

                   
                }
            } catch (SocketTimeoutException s) {
                System.out.println("Socket timed out!");
                break;
            } catch (IOException e) {
                e.printStackTrace();
                break;
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(CTF_Facility.class.getName()).log(Level.SEVERE, null, ex);
            } catch (Exception ex) {
                Logger.getLogger(CTF_Facility.class.getName()).log(Level.SEVERE, null, ex);
            }

        }
    }


    public void save_keys(String file_name, BigInteger modu, BigInteger expo)
            throws IOException {
        ObjectOutputStream oout = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(file_name)));
        try {
            oout.writeObject(modu);
            oout.writeObject(expo);
            oout.flush();
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            oout.close();
        }
    }

    public static void main(String[] args) throws InterruptedException {
        /**
         * ******************RUN THIS FILE FIRST*******************
         */
        try {
           // CTF_Facility key_gen = new CTF_Facility(3000);
      //     JEncrypRSA  key_gen = new JEncrypRSA;
            JEncrypRSA key_gen = new JEncrypRSA();
            key_gen.keyGeneration();
        } catch (IOException ex) {
            Logger.getLogger(CTF_Facility.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(CTF_Facility.class.getName()).log(Level.SEVERE, null, ex);
        }

        System.out.println("Start CLA_Agency");
        int cla_port = 7861;
        int votingelectionbooth_port = 7862;
        try {
            Thread cla_conn = new CTF_Facility(cla_port);
            cla_conn.start();
        } catch (IOException e) {
            System.err.println("**********Transmission error CLA_Agency**********");
            e.printStackTrace();
        }

        try {
            Thread votingelectionbooth_conn = new CTF_Facility(votingelectionbooth_port);
            votingelectionbooth_conn.start();
        } catch (IOException e) {
            System.err.println("**********Transmission Error Election_voter**********");
            e.printStackTrace();
        }
    }

}
