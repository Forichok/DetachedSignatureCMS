package ru.forichok;

import org.bouncycastle.tsp.TimeStampTokenInfo;

public interface TSAInfoBouncyCastle {

  /**
   * When a timestamp is created using TSAClientBouncyCastle,
   * this method is triggered passing an object that contains
   * info about the timestamp and the time stamping authority.
   * @param info a TimeStampTokenInfo object
   */
  public void inspectTimeStampTokenInfo(final TimeStampTokenInfo info);
}