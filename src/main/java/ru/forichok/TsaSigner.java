package ru.forichok;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

public class TsaSigner {

  public static Attribute createTspAttribute(byte[] data)
      throws GeneralSecurityException, TSPException, IOException {
    TsaClient tsaClient = new TsaClient("http://ca.signfiles.com/TSAServer.aspx");
    byte[] tsImprint = tsaClient.getMessageDigest().digest(data);
    TimeStampToken tsToken = tsaClient.getTimeStampToken(tsImprint);
    return new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
        new DERSet(tsToken.toCMSSignedData().toASN1Structure()));
  }

  public static byte[] signSignatureWithTSATimestamp(CMSSignedData signedData) throws GeneralSecurityException, TSPException, IOException {
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
