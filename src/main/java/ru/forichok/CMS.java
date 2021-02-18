package ru.forichok;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.util.Arrays;

public class CMS {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public static void main(String[] args) throws Exception {
    String[] arr = new String[20000];
    Arrays.fill(arr, " ");
    String text = "TEST CONTENT TO SIGN ";
    String tmp = String.join(text, arr);
    byte[] signData = tmp.getBytes();

    Organization.getJks();
  }

}
