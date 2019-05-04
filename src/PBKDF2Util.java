import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStoreException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

public class PBKDF2Util {
   
      public static void main(String args[]) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, GeneralSecurityException, IOException {
        
        //Adiciona Provider
        //Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleFipsProvider());
        
        //Instancia objetos Pessoa
        Pessoa alice = new Pessoa(0L, "Alice");
        Pessoa bob = new Pessoa(1L, "Bob");
             
        //Declara objetos úteis 
        PBKDF2Util obj = new PBKDF2Util();        
        String senhaChave;
        String senhaArmazenamentoKeyStore;
        String opcao;
        int it = 10000;
        
        Scanner input = new Scanner(System.in);                 
        
        System.out.println("Alice, digite a senha para sua chave: ");
        senhaChave = input.nextLine();

        System.out.println("Alice, digite a senha para armazenamento sua chave: ");
        senhaArmazenamentoKeyStore = input.nextLine();

        //Criptografia simétrica autenticada
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[128];
        sr.nextBytes(salt);
        //Hex.encodeHexString(salt);
        
        PBEKeySpec spec = new PBEKeySpec(senhaChave.toCharArray(), salt, it, 128);             
        SecretKeyFactory pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", "BCFIPS");
        SecretKey sk = pbkdf2.generateSecret(spec);
        String chaveDerivada = Hex.encodeHexString(sk.getEncoded());
        System.out.println("Chave derivada da senha gerada: " + chaveDerivada);

        SecureRandom random = new SecureRandom();
        byte iv[] = new byte[64];
        random.nextBytes(iv);
        
        
        
        
        System.out.println("IV gerado: " + Hex.encodeHexString(iv));

        storeSecretKey("meukeystore.bcfks", senhaArmazenamentoKeyStore.toCharArray(), senhaChave.toCharArray(), sk, iv);

        String mensagem1 = "Olá Bob!!! Quer conversar comigo?";
        
        IvParameterSpec ivParameter = new IvParameterSpec(iv);
        alice.setUltimaMensagemCifrada(obj.cifraMensagem(mensagem1, sk, ivParameter));

        System.out.println("Mensagem original: " + mensagem1);
        System.out.println("Mensagem cifrada: " + Hex.encodeHexString(alice.getUltimaMensagemCifrada()));

        //Bob
        
        System.out.println("Bob, digite a senha para obter sua chave: ");
        senhaChave = input.nextLine();

        System.out.println("Bob, digite a senha de armazenamento da sua chave: ");
        senhaArmazenamentoKeyStore = input.nextLine();

        SecretKey key = loadSecretKey(senhaArmazenamentoKeyStore.toCharArray(), senhaChave.toCharArray() );
        //byte[] ivLoaded = loadSecretIV(senhaArmazenamentoKeyStore.toCharArray(), senhaChave.toCharArray() ); //Problema para carregar IV

        System.out.println("Bob: mensagem cifrada recebida: " + Hex.encodeHexString(alice.getUltimaMensagemCifrada()));
        System.out.println("Bob: mensagem decifrada recebida: " + obj.decifraMensagem(alice.getUltimaMensagemCifrada(), key, ivParameter));
            
    }
        
    public byte[] cifraMensagem(String mensagem, SecretKey key, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
       Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
       cipher.init(Cipher.ENCRYPT_MODE, key, iv);
       byte[] enc = cipher.doFinal(mensagem.getBytes());
       return enc;
    }
    
    public String decifraMensagem(byte[] mensagem, SecretKey key, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
       Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
       cipher.init(Cipher.DECRYPT_MODE, key, iv);
       byte[] enc = cipher.doFinal(mensagem);
       return new String(enc);
    }
    
    public static void storeSecretKey(String storeFilename, char[] storePassword, char[] keyPass, SecretKey secretKey, byte[] iv) throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance("JCEKS"); //https://stackoverflow.com/questions/39431198/multi-platform-java-keystore        
        keyStore.load(null, null); //Cria do zero o KeyStore
        keyStore.store(new FileOutputStream("meukeystore.bcfks"), storePassword); //Salva o KeyStore com a senha passada pelo usuário

        keyStore.load(new FileInputStream("meukeystore.bcfks"), storePassword); //Carrega o KeyStore salvo
        keyStore.setKeyEntry("pbkdf2", secretKey, keyPass, null);        
        keyStore.store(new FileOutputStream("meukeystore.bcfks"), storePassword);
    }
    
    public static SecretKey loadSecretKey(char[] storePassword, char[] keyPass) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, FileNotFoundException, IOException, CertificateException, NoSuchProviderException{
        KeyStore keyStore = KeyStore.getInstance("JCEKS"); //JCEKS
        keyStore.load(new FileInputStream("meukeystore.bcfks"), storePassword);
        SecretKey key = (SecretKey) keyStore.getKey("pbkdf2", keyPass);
        System.out.println("Chave = " + Hex.encodeHexString(key.getEncoded()));
        return key;
    }
    
//    public static byte[] loadSecretIV(char[] storePassword, char[] keyPass) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, FileNotFoundException, IOException, CertificateException{
//        KeyStore keyStore = KeyStore.getInstance("JCEKS");
//        keyStore.load(new FileInputStream("meukeystore.bcfks"), storePassword);
//        Key iv = keyStore.getKey("iv", keyPass);
//        System.out.println("IV = " + Hex.encodeHexString(iv.getEncoded()));
//        return iv.getEncoded();
//    }
    
        
    
}
