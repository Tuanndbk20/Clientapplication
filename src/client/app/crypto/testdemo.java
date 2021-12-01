package client.app.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.math.ec.ECPoint;

import client.app.util.Constants;


public class testdemo {
	private static ECPrivateKeyParameters privateKey;
	private static ECPublicKeyParameters publicKey;
	private static ECPublicKeyParameters publicKeyDAS;
	
	private static byte[] ECQVRandom; // u
	private static byte[] resRegRandom; // c
	private static byte[] resRegRandomZ; // z
	private static byte[] symmetricSessionKey; // SK
	
	private static String toHex(String arg) {
		return String.format("%02x", new BigInteger(1, arg.getBytes())); // string.getBytes() method does the encoding
																			// of string into the sequence of bytes and
																			// keeps it in an array of bytes.
	}
	
	private static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) // 1 byte 8 bit >>shift 4 bit high
					+ Character.digit(s.charAt(i + 1), 16)); // 4 bit low
		}
		return data;
	}
	
	/* Perform SHA256 and return the result */
	private static byte[] sha256(byte[] data) {
		SHA256Digest digest = new SHA256Digest();
		byte[] hash = new byte[digest.getDigestSize()]; // tieu
		digest.update(data, 0, data.length); //
		digest.doFinal(hash, 0);
		return hash;
	}
	
	private static byte[] concatByteArrays(byte[] a, byte[] b) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try {
			outputStream.write(a);
			outputStream.write(b);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] concatResult = outputStream.toByteArray();
		return concatResult;
	}
	
	private static String toHex(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}
	/* Convert long to byte array */
	private static byte[] longToByteArray(long value) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(value);
		return buffer.array();

	}
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String sepSymb = "||";
		byte[] resNameBytes = hexStringToByteArray(toHex("temperature")); // Rn = resNameBytes
		byte[] typeSubBytes = hexStringToByteArray(toHex("silver")); // Tr = typeSubBytes
		// Add separation symbol to resource name
		byte[] cleartext = concatByteArrays(resNameBytes, hexStringToByteArray(toHex(sepSymb))); // cleartext = Sub chua ma hoa
		// Add type of subscription
		cleartext = concatByteArrays(cleartext, typeSubBytes);

		cleartext = concatByteArrays(cleartext, hexStringToByteArray(toHex(sepSymb)));
		// Add IDu
		cleartext = concatByteArrays(cleartext, hexStringToByteArray(toHex(Constants.clientID)));
		cleartext = concatByteArrays(cleartext, hexStringToByteArray(toHex(sepSymb)));
		// Add Kr
		
		//cleartext = concatByteArrays(cleartext, Kr);
		// Add random number
		//cleartext = concatByteArrays(cleartext, resRegRandom); // c= resRegRandom
		cleartext= resNameBytes;
		System.out.println("cleartext: " + toHex(cleartext)); // Sub khi chua ma hoa
		
		X9ECParameters ecp = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(), ecp.getG(), ecp.getN(), ecp.getH(),
				ecp.getSeed());
		
		SecureRandom random = new SecureRandom();
		resRegRandomZ = new byte[Constants.randomNumberSize]; // resRegRandomZ= z
		random.nextBytes(resRegRandomZ); // Fill the array with random bytes
		
		/* Elliptic curve multiplication using the random number */
		ECPoint pointZ = domainParams.getG().multiply(new BigInteger(resRegRandomZ)); 
		byte[] encodedZ = pointZ.getEncoded(true); // encodedZ= Z

		/* Kz=H(z*PDAS||Tr) */

		/* Elliptic curve multiplication */
		ECPoint secretPointZ = publicKeyDAS.getQ().multiply(new BigInteger(resRegRandomZ));
		byte[] encodedSecretPointZ = secretPointZ.getEncoded(true);

		/* Generate a timestamp */
		Date date = new Date();
		long regTimestamp = date.getTime();
		byte[] regTimestampBytes = longToByteArray(regTimestamp);
		
		/* Concatenate the encoded secret point with the timestamp */
		byte[] secretTimestampConcatZ = concatByteArrays(encodedSecretPointZ, regTimestampBytes);

		/* Do the sha256 of the secretTimestampConcat byte array */
		byte[] Kz = sha256(secretTimestampConcatZ);

		System.out.println("Symmetric key Kz: " + toHex(Kz));

		
		// Generate a nonce (12 bytes) to be used for AES_256_CCM_8
		
		random = new SecureRandom();
		byte[] nonce = new byte[Constants.nonceSize];
		random.nextBytes(nonce); // Fill the nonce with random bytes
		System.out.println("nonce = " + toHex(nonce)); // z dung ket hop vs kr de ma hoa sub

		// Encrypt the cleartext(Sub)
		CCMBlockCipher ccm = new CCMBlockCipher(new AESEngine());
		// ccm.init(true, new ParametersWithIV(new KeyParameter(Kr), nonce));
		ccm.init(true, new ParametersWithIV(new KeyParameter(Kz), nonce));
		byte[] ciphertext = new byte[cleartext.length + 8];
		int len = ccm.processBytes(cleartext, 0, cleartext.length, ciphertext, 0);
		try {
			len += ccm.doFinal(ciphertext, len);
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("Ciphertext: " + toHex(ciphertext));
	}

}
