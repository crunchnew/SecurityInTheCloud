package crypto;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {
 
  private static final String KEYSTORE_FILE = "keys.pfx";
  private static final String PROVIDER = "SunJCE";
  private static final String KEYSTORE_TYPE = "PKCS12";

  private static final String SYMMETRICAL_CIPHER = "AES";
  private static final String SYMMETRICAL_MODE = "CBC";
  private static final String SYMMETRICAL_PADDING = "PKCS5Padding";
  
  private static final String ASYMMETRICAL_CIPHER = "RSA";
  private static final String ASYMMETRICAL_MODE = "ECB";
  private static final String ASYMMETRICAL_PADDING = "PKCS1Padding";
  
  private static final String  CERTIFICATE = "X.509";
  private static final String  CERTIFICATE_FILE = "pub_key_cert.crt";
  private static final String  POSTFIX_FILE = "_enc";
  
  private static final String KEY_ALIAS = "mykey";
  
  private static final String EXCEPTION_MESSAGE_CORRUPTED_KEY  = "Corrupted key.";
  private static final String EXCEPTION_MESSAGE_WRONG_KEY_SIZE = "Could not read key size.";
  
  private static final byte[] dataForInitializeVector = new byte[] { (byte) 0x3d,
      (byte) 0x02, (byte) 0x8c, (byte) 0x6b, (byte) 0xed, (byte) 0x8e,
      (byte) 0xb6, (byte) 0x63, (byte) 0x66, (byte) 0x7f, (byte) 0x32,
      (byte) 0xa5, (byte) 0x92, (byte) 0xd3, (byte) 0x21, (byte) 0x57 };
  
  private static final IvParameterSpec initalizeVector = new IvParameterSpec(dataForInitializeVector);
  
  private static final int BUFFER_SIZE = 2048; 

  private static char keyStorePassword[] ;
  
  public static void setKeyStorePassword(char password[]) {
    keyStorePassword = password;
  }
  
  //============================================================================================================================================

  public static boolean isPasswordCorrect() {
        
    try {
      KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
      keyStore.load(new FileInputStream(KEYSTORE_FILE),keyStorePassword);
    }
     catch (Exception e) {      
      System.out.println(e.getMessage());
      return false;
    }
    return true;
   
  }

  // ================================================================== begin encrypt ========================================================================== 
  
  public static void encyptFile(String file) throws GeneralSecurityException, IOException {

    int nBytesRead;
    byte[] buffer = new byte[BUFFER_SIZE];
    
    FileInputStream fileInputStream;
    CipherInputStream ciferInputStream;
    FileOutputStream fileOutpurStream;
    
    KeyGenerator sessionKey;
    
    sessionKey = KeyGenerator.getInstance(SYMMETRICAL_CIPHER, PROVIDER);   
    SecretKey key = sessionKey.generateKey();    
    Cipher aes = Cipher.getInstance( SYMMETRICAL_CIPHER + "/" + SYMMETRICAL_MODE + "/" + SYMMETRICAL_PADDING, PROVIDER );
    
    aes.init(Cipher.ENCRYPT_MODE, key, initalizeVector);

    fileInputStream = new FileInputStream(file);
    ciferInputStream = new CipherInputStream(fileInputStream, aes);
    fileOutpurStream = new FileOutputStream(file + POSTFIX_FILE);

    byte[] keyData = encryptKey(key.getEncoded());
    writeInt(fileOutpurStream, keyData.length);
    fileOutpurStream.write(keyData);

    while ((nBytesRead = ciferInputStream.read(buffer)) > 0) {      
      fileOutpurStream.write(buffer, 0, nBytesRead);      
    }
    
    ciferInputStream.close();
    fileOutpurStream.close();  

  }
  
  private static void writeInt(OutputStream os, int v) throws IOException {
    os.write((v >> 24) & 0xff);
    os.write((v >> 16) & 0xff);
    os.write((v >> 8) & 0xff);
    os.write(v & 0xff);
  }
  
  static private byte[] encryptKey(byte[] key) throws GeneralSecurityException, IOException  {
    
    FileInputStream fin = new FileInputStream(CERTIFICATE_FILE);
    CertificateFactory f = CertificateFactory.getInstance(CERTIFICATE);
    X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
    PublicKey publicKey = certificate.getPublicKey();
        
    Cipher cipher = Cipher.getInstance(ASYMMETRICAL_CIPHER + "/" + ASYMMETRICAL_MODE + "/" + ASYMMETRICAL_PADDING, PROVIDER);
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return cipher.doFinal(key);
  }

  // ================================================================== end encrypt ==========================================================================
  
  
  //================================================================== begin decrypt ==========================================================================
  
  public static void decryptFile(String file) throws GeneralSecurityException, IOException {
    
    byte[] buffer = new byte[BUFFER_SIZE];
    int nBytesRead;
               
    FileInputStream fileInputStream = new FileInputStream(file);

    int keyLength = readInt(fileInputStream);
    if (keyLength < 0) throw new IOException(EXCEPTION_MESSAGE_CORRUPTED_KEY);
    byte[] keyData = new byte[keyLength];
    if (fileInputStream.read(keyData) != keyLength) throw new IOException(EXCEPTION_MESSAGE_CORRUPTED_KEY);
      
    keyData = decryptKey(keyData);            
    Key key = new SecretKeySpec(keyData, SYMMETRICAL_CIPHER);
      
    Cipher aes = Cipher.getInstance(SYMMETRICAL_CIPHER + "/" + SYMMETRICAL_MODE + "/" + SYMMETRICAL_PADDING, PROVIDER);
    aes.init(Cipher.DECRYPT_MODE, key, initalizeVector);
      
    FileOutputStream fos = new FileOutputStream(file + "_dec");
    CipherOutputStream cos = new CipherOutputStream(fos, aes);

    while ((nBytesRead = fileInputStream.read(buffer)) > 0) cos.write(buffer, 0, nBytesRead);

    cos.close();  
    fos.close();

  }
  
  private static int readInt(InputStream is) throws IOException {
    
    byte[] buf = new byte[4];
    
    if (is.read(buf) != 4) throw new IOException(EXCEPTION_MESSAGE_WRONG_KEY_SIZE);
    
    int x = ((int) (buf[0] << 24) & 0xff000000) | ((int) (buf[1] << 16) & 0xff0000) | ((int) (buf[2] << 8) & 0xff00) | ((int) buf[3] & 0xff);
    
    System.out.println("Liczba zakodowana[" + x + "]");
    
    return ((int) (buf[0] << 24) & 0xff000000) | ((int) (buf[1] << 16) & 0xff0000) | ((int) (buf[2] << 8) & 0xff00) | ((int) buf[3] & 0xff);
  }

  private static byte[] decryptKey(byte[] key) throws GeneralSecurityException, IOException {
  
    KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
    keyStore.load(new FileInputStream(KEYSTORE_FILE), keyStorePassword);
    PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS,keyStorePassword);
    

    Cipher cipher = Cipher.getInstance(ASYMMETRICAL_CIPHER + "/" + ASYMMETRICAL_MODE + "/" + ASYMMETRICAL_PADDING, PROVIDER);    
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    return cipher.doFinal(key);     

  }
  
  //================================================================== end decrypt ==========================================================================
}
