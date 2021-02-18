package ru.forichok;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import sun.misc.BASE64Encoder;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import java.util.concurrent.TimeUnit;

class Organization {

  private static final String ALIAS = "A-1";

  private KeyStore keyStore;

  Organization() throws Exception {

  }

  private Organization(KeyStore keyStore) {
    this.keyStore = keyStore;
  }

  X509Certificate cert() throws Exception {
    return (X509Certificate) keyStore.getCertificate(ALIAS);
  }

//  private PrivateKey key() throws Exception {
//
//  }


  public static KeyStore getJks() throws Exception {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECGOST3410", "BC");
    keyPairGenerator.initialize(new ECGenParameterSpec("GostR3410-2001-CryptoPro-A"));
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name("CN=Me");
    org.bouncycastle.asn1.x500.X500Name issuer = subject; // self-signed
    BigInteger serial = BigInteger.ONE; // serial number for self-signed does not matter a lot
    Date notBefore = new Date();
    Date notAfter = new Date(notBefore.getTime() + TimeUnit.DAYS.toMillis(365));

    org.bouncycastle.cert.X509v3CertificateBuilder certificateBuilder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
        issuer, serial,
        notBefore, notAfter,
        subject, keyPair.getPublic()
    );

    org.bouncycastle.cert.X509CertificateHolder certificateHolder = certificateBuilder.build(
        new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("GOST3411withECGOST3410")
            .build(keyPair.getPrivate())
    );
    org.bouncycastle.cert.jcajce.JcaX509CertificateConverter certificateConverter = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter();
    X509Certificate certificate = certificateConverter.getCertificate(certificateHolder);


    KeyStore keyStore = KeyStore.getInstance("JKS");
    keyStore.load(null, null); // initialize new keystore

    keyStore.setEntry(
        "alias",
        new KeyStore.PrivateKeyEntry(
            keyPair.getPrivate(),
            new X509Certificate[]{certificate}
        ),
        new KeyStore.PasswordProtection("entryPassword".toCharArray())
    );
    keyStore.store(new FileOutputStream("test.jks"), "keystorePassword".toCharArray());
    loadKeystoreData(keyStore);
    return keyStore;
  }

  public static void loadKeystoreData(KeyStore keystore) throws Exception {
    Enumeration<String> aliases = keystore.aliases();

    HashMap<String, Key> keys = new HashMap<>();
    HashMap<String, X509Certificate> certificates = new HashMap<>();

    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();

      if (keystore.isKeyEntry(alias)) {
        Key key = keystore.getKey(alias, "entryPassword".toCharArray());
        keys.put(alias.toLowerCase(), key); //any key,value collection

        Certificate certificate = keystore.getCertificate(alias);
        if (certificate instanceof X509Certificate)
          certificates.put(alias.toLowerCase(), (X509Certificate) certificate); //any key,value collection
        sign((PrivateKey) key, (X509Certificate) certificate);
      }
    }
  }

  public static byte[] sign(PrivateKey privateKey, X509Certificate certificate) throws Exception {
    String[] arr = new String[20000];
    Arrays.fill(arr, " ");
    String text = "TEST CONTENT TO SIGN ";
    String tmp = String.join(text, arr);
    byte[] signData = tmp.getBytes();

    CMSProcessableByteArray msg = new CMSProcessableByteArray(signData);

    List certList = new ArrayList();
    certList.add(certificate);

    Store certs = new JcaCertStore(certList);
    CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("GOST3411WITHECGOST3410-2012-256").setProvider("BC").build(privateKey);

    gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(signer, certificate));
    gen.addCertificates(certs);

    CMSSignedData sigData = gen.generate(msg, false);
    byte[] sign = sigData.getEncoded();
    byte[] tsaSigned = createTimeStampedSigner(sigData);
    try {
      Date time = verifyTimeStampedSigner(tsaSigned);
      System.out.printf("TSA verification has been passed. Generation time: %s%n", time);
    } catch (Exception e) {
      System.out.println("TSA verification has been failed");
    }

    BASE64Encoder encoder = new BASE64Encoder();
    System.out.printf("DEFAULT SIGNED:\n%s\n%n", encoder.encode(sign));
    System.out.printf("TSA SIGNED:\n%s\n%n", encoder.encode(tsaSigned));


    verify(signData, tsaSigned);
    return tsaSigned;
  }

  public static void verify(byte[] data, byte[] signature) {
    boolean checkResult;
    CMSProcessable signedContent = new CMSProcessableByteArray(data);
    CMSSignedData signedData = null;
    try {
      signedData = new CMSSignedData(signedContent, signature);
    } catch (CMSException e) {
      System.out.println("Unable to create CMS signed data");
    }

    try {
      Store<X509CertificateHolder> certStoreInSing = signedData.getCertificates();
      SignerInformation signer = signedData.getSignerInfos().getSigners().iterator().next();

      Collection certCollection = certStoreInSing.getMatches(signer.getSID());
      Iterator certIt = certCollection.iterator();

      X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
      X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
      checkResult = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certificate));

      System.out.printf("Certificate is: %s", checkResult ? "ok" : "incorrect");
    } catch (Exception ex) {
      System.out.println("Certificate verification has been failed.");
    }
  }

  public static Attribute createTspAttribute(byte[] data)
      throws GeneralSecurityException, TSPException, IOException {
    TsaClient tsaClient = new TsaClient("http://ca.signfiles.com/TSAServer.aspx");
    if (tsaClient != null) {
      byte[] tsImprint = tsaClient.getMessageDigest().digest(data);
      TimeStampToken tsToken = tsaClient.getTimeStampToken(tsImprint);
      return new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
          new DERSet(tsToken.toCMSSignedData().toASN1Structure()));
    }
    return null;
  }

  public static byte[] createTimeStampedSigner(CMSSignedData signedData) throws GeneralSecurityException, TSPException, IOException {
    SignerInformation signer = signedData.getSignerInfos().iterator().next();
    ASN1EncodableVector timestampVector = new ASN1EncodableVector();
    timestampVector.add(createTspAttribute(signer.getSignature()));
    AttributeTable at = new AttributeTable(timestampVector); // create replacement signer
    signer = SignerInformation.replaceUnsignedAttributes(signer, at); // create replacement SignerStore
    SignerInformationStore newSignerStore = new SignerInformationStore(signer);
// replace the signers in the signed data object
    return CMSSignedData.replaceSigners(signedData, newSignerStore).getEncoded();
  }

  public static Date verifyTimeStampedSigner(byte[] cmsSignedData)
      throws OperatorCreationException, GeneralSecurityException, CMSException, IOException, TSPException {
    CMSSignedData signedData = new CMSSignedData(cmsSignedData);
    SignerInformation signer = signedData.getSignerInfos().iterator().next();
    TimeStampToken tspToken = new TimeStampToken(ContentInfo.getInstance(signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken).getAttributeValues()[0]));
    Collection certCollection = tspToken.getCertificates().getMatches(tspToken.getSID());
    Iterator certIt = certCollection.iterator();
    X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
// this method throws an exception if validation fails.
    tspToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
    return tspToken.getTimeStampInfo().getGenTime();
  }

}
