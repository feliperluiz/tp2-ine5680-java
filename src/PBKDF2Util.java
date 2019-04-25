import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Scanner;
import javax.crypto.SecretKey;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * User: Carla
 * Date: 1 de setembro de 2015
 */

public class PBKDF2Util {
    
    /**
     * Gerar chave derivada da senha
     * @param key
     * @param salt
     * @param iterations
     * @return
     */
    public static String generateDerivedKey(String password, String salt, Integer iterations) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, 128);
        SecretKeyFactory pbkdf2 = null;
        String derivedPass = null;
        try {
            pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            SecretKey sk = pbkdf2.generateSecret(spec);
            derivedPass = Hex.encodeHexString(sk.getEncoded());
            
            storeSecretKey("meukeystore.bcfks", "password".toCharArray(), "pbkdf2", password.toCharArray(), sk);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return derivedPass;
    }
    
    //Tenho PBEKeySpec e SecretKey 
    
    /*Usado para gerar o salt  */
    public String getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        //SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return Hex.encodeHexString(salt);
    }

    public static void main(String args[]) throws NoSuchAlgorithmException {
        
        // Install Provider FIPS
        Security.addProvider(new BouncyCastleFipsProvider());
        
        Pessoa alice = new Pessoa(0L, "Alice");
        Pessoa bob = new Pessoa(1L, "Bob");
             
        PBKDF2Util obj = new PBKDF2Util();        
        
        String senha;
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
        
        //Alice:
        
        if (umaPessoa != null && umaPessoa.getNome().equals("Alice")) {
            System.out.println("Digite a senha: ");
            senha = input.nextLine(); //senha = "123456789";
            salt = obj.getSalt();

            System.out.println("Senha original = " + senha);
            System.out.println("IV gerado = " + salt);
            System.out.println("Numero de iteracoes = " + it);

            String chaveDerivada = generateDerivedKey(senha, salt, it);

            System.out.println("Chave derivada da senha = " + chaveDerivada );
        }
        
        
    }
    
    public static void storeSecretKey(String storeFilename, char[] storePassword, String alias, char[] keyPass, SecretKey secretKey)
            throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance("PBKDF2WithHmacSHA512");
        keyStore.load(new FileInputStream(storeFilename), storePassword);
        //keyStore.load(null, null);

        keyStore.setKeyEntry(alias, secretKey, keyPass, null);
        keyStore.store(new FileOutputStream(storeFilename), storePassword);
    }


}
