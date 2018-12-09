package console;

import java.io.Console;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.StringTokenizer;

import crypto.*;

public class DBoxApp {

  private static final String promptPrefix = "DropBoxDir@:"; 
  private static String prompt = "";
  private static final String promptPostfix = " $ ";
  private static Console console;
  
  
  private static String getPrompt() {
    return promptPrefix + prompt + promptPostfix;   
  }
  
  
  private static void getLine(String line) {
  
    
    StringTokenizer st = new StringTokenizer(line);

    st.countTokens();
    for (int i = 1; st.hasMoreTokens(); i++) {
        System.out.println("Token "+i+":"+st.nextToken());
    }
      
    console.printf("\n");
  }
  
  
  public static void login() throws IOException, InterruptedException {
    
    new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
    
    console = System.console();
    if (console == null)
    {
      System.out.println("Couldn't get Console instance");
      System.exit(0);
    }
    
    
    console.printf("\"Security in the cloud\" v 1.0 2018 \n \n");
    
    Crypto.setKeyStorePassword( console.readPassword("Enter your secret password: > ") );
    //if ( ! Crypto.isPasswordCorrect() )  System.exit(0);
    
    for(;;) {
      console.printf( getPrompt() );
      getLine( console.readLine() );      
    }
    
  }

  public static void main(String[] args) throws IOException, GeneralSecurityException, InterruptedException {
   
      login();
  }  
}
