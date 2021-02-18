package ru.forichok;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Encoder;

import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;
import java.util.Date;

public class CMS {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public static void main(String[] args) throws Exception {
    String[] arr = new String[20000];
    Arrays.fill(arr, " ");
    String text = "TEST CONTENT TO SIGN ";
    String tmp = String.join(text, arr);
    byte[] data = tmp.getBytes();

    KeyStore keystore = KeyStoreFactory.getKeystore();
    Organization org = new Organization(keystore);

    CMSSignedData signData = org.sign(data, org.getPrivateKey(), org.getCertificate());

    byte[] signature = signData.getEncoded();
    byte[] tsaSignature = TsaSigner.signSignatureWithTSATimestamp(signData);
    try {
      Date time = TsaSigner.verifyTimeStampedSigner(tsaSignature);
      System.out.printf("TSA verification has been passed. Generation time: %s\n\n", time);
    } catch (Exception e) {
      System.out.println("TSA verification has been failed.\n");
    }

    BASE64Encoder encoder = new BASE64Encoder();
    System.out.printf("DEFAULT SIGNED:\n%s\n%n", encoder.encode(signature));
    System.out.printf("TSA SIGNED:\n%s\n%n", encoder.encode(tsaSignature));

    SignatureVerifier.verify(data, signature);
  }

}
