package id.co.swamedia;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HmacUtils {

    public static String generateHmac(String data, String key, String algorithm) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), algorithm);
            Mac mac = Mac.getInstance(algorithm);
            mac.init(secretKey);
            byte[] hmacData = mac.doFinal(data.getBytes());
            return Hex.encodeHexString(hmacData);
        } catch (Exception e) {
            throw new RuntimeException("Failed to calculate HMAC: " + e.getMessage(), e);
        }
    }
}
