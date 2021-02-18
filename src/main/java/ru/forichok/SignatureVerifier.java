package ru.forichok;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

public class SignatureVerifier {
  public static boolean verify(byte[] data, byte[] signature) {
    boolean checkResult;
    CMSProcessable signedContent = new CMSProcessableByteArray(data);
    CMSSignedData signedData = null;
    try {
      signedData = new CMSSignedData(signedContent, signature);
    } catch (CMSException e) {
      System.out.println("Unable to create CMS signed data\n");
    }

    try {
      Store<X509CertificateHolder> certStoreInSing = signedData.getCertificates();
      SignerInformation signer = signedData.getSignerInfos().getSigners().iterator().next();

      Collection certCollection = certStoreInSing.getMatches(signer.getSID());
      Iterator certIt = certCollection.iterator();

      X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
      X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
      checkResult = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certificate));

      System.out.printf("Certificate is: %s\n", checkResult ? "ok" : "incorrect");
    } catch (Exception ex) {
      System.out.println("Certificate verification has been failed.\n");
      return false;
    }
    return checkResult;
  }
}
