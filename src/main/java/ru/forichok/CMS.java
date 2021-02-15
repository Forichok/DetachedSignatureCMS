package ru.forichok;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.Store;
import sun.misc.BASE64Encoder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

public class CMS {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public static void main(String[] args) throws Exception {
    String[] arr = new String[200000];
    Arrays.fill(arr, " ");
    String text = "TEST CONTENT TO SIGN ";
    String tmp = String.join(text, arr);
    byte[] signData = tmp.getBytes();

    Organization org1 = new Organization();
    X509Certificate cert1 = org1.cert();
    SignerInfoGenerator siGen1 = org1.createSignerInfoGenerator();
    X509Certificate[] certs = new X509Certificate[]{cert1};
    SignerInfoGenerator[] siGenerator = new SignerInfoGenerator[]{siGen1};

    byte[] sign = getSign(signData, certs, siGenerator);

    verifySign(signData, sign);
    verifyIncorrectSing(signData, sign);
    verifyCorruptedSing(signData, sign);
  }


  public static byte[] getSign(byte[] signData, X509Certificate[] certs, SignerInfoGenerator[] siGenerator) throws Exception {

    CMSSignedData sigData = signData(signData, certs, siGenerator);
    System.out.println("SIGNATURE DETACHED: " + sigData.isDetachedSignature());

    BASE64Encoder encoder = new BASE64Encoder();

    String signedContent = encoder.encode((byte[]) sigData.getSignedContent().getContent());
    System.out.println("(" + signedContent.length() + ") Content: " + signedContent + "\n");

    String envelopedData = encoder.encode(sigData.getEncoded());
    System.out.println("(" + envelopedData.length() + ") SignedData: " + envelopedData);
    System.out.println("\n");
    return sigData.getEncoded();
  }

  public static void verifyCorruptedSing(byte[] signData, byte[] sign) throws Exception {
    sign[1024] = 4;
    verifySign(signData, sign);
  }

  public static void verifyIncorrectSing(byte[] signData, byte[] sign) throws Exception {
    sign[1273] = 4;
    verifySign(signData, sign);
  }

  public static void verifySign(byte[] signedText, byte[] signBytes) {
    Security.addProvider(new BouncyCastleProvider());

    InputStream is = new ByteArrayInputStream(signedText);
    try {
      CMSSignedDataParser sp = new CMSSignedDataParser(new BcDigestCalculatorProvider(), new CMSTypedStream(is), signBytes);
      CMSTypedStream signedContent = sp.getSignedContent();

      signedContent.drain();

      Store certStore = sp.getCertificates();

      SignerInformationStore signers = sp.getSignerInfos();
      Collection c = signers.getSigners();
      Iterator it = c.iterator();
      while (it.hasNext()) {
        SignerInformation signer = (SignerInformation) it.next();
        Collection certCollection = certStore.getMatches(signer.getSID());

        Iterator certIt = certCollection.iterator();

        X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();


        if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder))) {
          System.out.println("Verify failed\n");
        } else {
          System.out.println("Verify success\n");
        }
      }
    } catch (Exception e) {
      System.out.println("Verify failed. Sign is corrupted.\n");
    }
  }


  private static CMSSignedData signedDataFrom(byte[] signedData) throws CMSException, IOException {
    ByteArrayInputStream inputStream = new ByteArrayInputStream(signedData);
    ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);
    return new CMSSignedData(ContentInfo.getInstance(asnInputStream.readObject()));
  }

  private static CMSSignedData signData(byte[] data, X509Certificate[] signingCertificate, SignerInfoGenerator[] generators) throws Exception {
    CMSTypedData cmsData = new CMSProcessableByteArray(data);

    CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
    Arrays.asList(generators).forEach(cmsGenerator::addSignerInfoGenerator);

    Store certs = new JcaCertStore(Arrays.asList(signingCertificate));
    cmsGenerator.addCertificates(certs);

    return cmsGenerator.generate(cmsData, false);
  }

}
