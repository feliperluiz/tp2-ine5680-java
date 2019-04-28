import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

public class PBKDF2Util {
    
    private Cipher cipher;

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
        String salt;
        int it = 10000;
        
        Scanner input = new Scanner(System.in);
        System.out.println("Digite 1 se você for a Alice ou 2 se você for o Bob: ");
        opcao = input.nextLine();      
        Pessoa umaPessoa = null;
        switch (opcao) { 
            case "1":
            umaPessoa = new Pessoa(0L, "Alice");
            break;
            case "2":
            umaPessoa = new Pessoa(0L, "Bob");
            break;
            default:
            System.out.println("Opção inválida!");
        }
                 
        if (umaPessoa != null) {
            if (umaPessoa.getNome().equals("Alice")) {
                System.out.println("Digite a senha para sua chave: ");
                senhaChave = input.nextLine();

                System.out.println("Digite a senha para armazenamento sua chave: ");
                senhaArmazenamentoKeyStore = input.nextLine();

                //Criptografia simétrica autenticada
                salt = obj.getSalt();
                PBEKeySpec spec = new PBEKeySpec(senhaChave.toCharArray(), salt.getBytes(), it, 128);             
                SecretKeyFactory pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", "BCFIPS");
                SecretKey sk = pbkdf2.generateSecret(spec);
                String chaveDerivada = Hex.encodeHexString(sk.getEncoded());
                System.out.println("Chave derivada da senha gerada: " + chaveDerivada);

                //Criando IV
                SecureRandom random = new SecureRandom();
                byte iv[] = new byte[16];
                random.nextBytes(iv);
                System.out.println("IV gerado: " + Hex.encodeHexString(iv));

                storeSecretKey("meukeystore.bcfks", senhaArmazenamentoKeyStore.toCharArray(), senhaChave.toCharArray(), sk, iv);

                String mensagem1 = "Olá Bob!!! Quer conversar comigo?";
                String mensagemCifrada = obj.cifraMensagem(mensagem1, sk, iv);

                System.out.println("Mensagem original: " + mensagem1);
                System.out.println("Mensagem cifrada: " + mensagemCifrada);
            } else {
                
            }
        }
        
     }
   
    public String cifraMensagem(String mensagem, SecretKey key, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
       cipher = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
       cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
       byte[] enc = cipher.doFinal(mensagem.getBytes());
       String mensagemCifrada = Hex.encodeHexString(enc);
       return mensagemCifrada;
    }
    
    public static void storeSecretKey(String storeFilename, char[] storePassword, char[] keyPass, SecretKey secretKey, byte[] iv) throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance("JCEKS"); //https://stackoverflow.com/questions/39431198/multi-platform-java-keystore        
        keyStore.load(null, null); //Cria do zero o KeyStore
        keyStore.store(new FileOutputStream("meukeystore.bcfks"), storePassword); //Salva o KeyStore com a senha passada pelo usuário

        keyStore.load(new FileInputStream("meukeystore.bcfks"), storePassword); //Carrega o KeyStore salvo
        keyStore.setKeyEntry("pbkdf2", secretKey, keyPass, null);
        keyStore.setKeyEntry("iv", iv, null);
        keyStore.store(new FileOutputStream("meukeystore.bcfks"), storePassword);
    }
    
           
    /*Usado para gerar o salt  */
    public String getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = new SecureRandom();
        //SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return Hex.encodeHexString(salt);
    }
}