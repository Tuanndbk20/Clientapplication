package client.app.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Scanner;

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

public class CryptographicOperations {

	private static ECPrivateKeyParameters privateKey;
	private static ECPublicKeyParameters publicKey;
	private static ECPublicKeyParameters publicKeyDAS;
	// The ECQV is a very efficient algorithm that allows a TTP
	// to issue an implicit certificate and derive the key pair
	// to the client without the necessity of a secure channel between TTP and
	// client.
	private static byte[] ECQVRandom; // u
	private static byte[] resRegRandom; // c
	private static byte[] resRegRandomZ; // z
	private static byte[] symmetricSessionKey; // SK

	// private static String resName = null;

	/* Transform a byte array in an hexadecimal string */
	private static String toHex(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	/*
	 * Transform an hexadecimal string in byte array (It works if the string only
	 * contains the hexadecimal characters)
	 */
	private static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) // 1 byte 8 bit >>shift 4 bit high
					+ Character.digit(s.charAt(i + 1), 16)); // 4 bit low
		}
		return data;
	}

	/* Convert a string representation in its hexadecimal string */
	private static String toHex(String arg) {
		return String.format("%02x", new BigInteger(1, arg.getBytes())); // string.getBytes() method does the encoding
																			// of string into the sequence of bytes and
																			// keeps it in an array of bytes.
	}

	/* Convert long to byte array */
	private static byte[] longToByteArray(long value) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(value);
		return buffer.array();

	}

	/* Concatenation of two byte arrays */
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

	/* Perform SHA256 and return the result */
	private static byte[] sha256(byte[] data) {
		SHA256Digest digest = new SHA256Digest();
		byte[] hash = new byte[digest.getDigestSize()]; // tieu
		digest.update(data, 0, data.length); //
		digest.doFinal(hash, 0);
		return hash;
	}

	/* Return an encoded elliptic curve point obtained as U = uG */
	public static String getUfromRandom() {
		// Get domain parameters for example curve secp256r1
		X9ECParameters ecp = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(), ecp.getG(), ecp.getN(), ecp.getH(),
				ecp.getSeed());
		/* Generate a random number with a fixed size of 32 bytes */
		SecureRandom random = new SecureRandom();
		ECQVRandom = new byte[Constants.randomNumberSize];
		random.nextBytes(ECQVRandom); // Fill the array with random bytes
		System.out.println("u = " + toHex(ECQVRandom));

		/* Elliptic curve multiplication using the random number */
		ECPoint pointU = domainParams.getG().multiply(new BigInteger(ECQVRandom));
		byte[] encodedU = pointU.getEncoded(true);
		System.out.println("U = " + toHex(encodedU)); // step 2:
		return toHex(encodedU);
	}

	/*
	 * Generate the public and private keys of the client using information received
	 * from the dynamic authorization server
	 */
	public static void generateECKeyPair(String cert, String q) {
		// Get domain parameters for example curve secp256r1
		X9ECParameters ecp = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(), ecp.getG(), ecp.getN(), ecp.getH(),
				ecp.getSeed());
		byte[] certBytes = hexStringToByteArray(cert);
		BigInteger qBigInt = new BigInteger(hexStringToByteArray(q));

		/*
		 * Calculation of the private key as d = H(cert||ID)u + q and public key as P =
		 * dG
		 */
		/* Concatenation of 2 bytes array */
		byte[] certIDconcat = concatByteArrays(certBytes, hexStringToByteArray(Constants.clientID));

		/* Do the sha256 of the certIDconcat byte array */
		byte[] hash = sha256(certIDconcat);

		/* Multiply for the random value u */
		BigInteger bigIntHash = new BigInteger(hash);
		BigInteger hashRandMult = bigIntHash.multiply(new BigInteger(ECQVRandom));

		/* Sum for the q value to obtain the private key */
		BigInteger privKey = hashRandMult.add(qBigInt);
		privateKey = new ECPrivateKeyParameters(privKey, domainParams);

		/*
		 * Perform elliptic curve multiplication operation to obtain the public key from
		 * the private key
		 */
		ECPoint pubKeyPoint = domainParams.getG().multiply(privateKey.getD());
		publicKey = new ECPublicKeyParameters(pubKeyPoint, domainParams);

		System.out.println("Private key: " + toHex(privateKey.getD().toByteArray()));
		System.out.println("Public key: " + toHex(publicKey.getQ().getEncoded(true)));
	}

	/*
	 * Check if the information received from the dynamic authorization server has
	 * not been tampered
	 */
	public static boolean verifyPublicKey(String encodedStringCert, String encodedStringPubKeyDAS) {
		// Get domain parameters for example curve secp256r1
		X9ECParameters ecp = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(), ecp.getG(), ecp.getN(), ecp.getH(),
				ecp.getSeed());
		byte[] encodedCert = hexStringToByteArray(encodedStringCert);
		/* Decode the certificate to obtain its elliptic curve point representation */
		ECPoint cert = ecp.getCurve().decodePoint(encodedCert);

		byte[] encodedPubKeyDAS = hexStringToByteArray(encodedStringPubKeyDAS);
		/*
		 * Decode the public key of the dynamic authorization server to obtain its point
		 * representation in the elliptic curve
		 */
		ECPoint pubKeyDASpoint = ecp.getCurve().decodePoint(encodedPubKeyDAS);
		publicKeyDAS = new ECPublicKeyParameters(pubKeyDASpoint, domainParams);
		System.out.println("Public key of DAS server: " + toHex(publicKeyDAS.getQ().getEncoded(true)));

		/* Compute the public key using H(cert||ID)cert + P_DAS */
		/* Concatenation of 2 bytes array */
		byte[] certIDconcat = concatByteArrays(encodedCert, hexStringToByteArray(Constants.clientID));

		/* Do the sha256 of the certIDconcat byte array */
		byte[] hash = sha256(certIDconcat);
		BigInteger bigIntHash = new BigInteger(hash);

		/* Elliptic curve point multiplication */
		ECPoint intermPoint = cert.multiply(bigIntHash);

		/*
		 * Sum intermPoint to the public key point of the dynamic authorization server
		 * to obtain the public key point of the client
		 */
		ECPoint pubKeyPoint = intermPoint.add(pubKeyDASpoint);

		if (pubKeyPoint.equals(publicKey.getQ())) {
			return true;
		} else {
			return false;
		}
	}

	public static String generateResourceRegistraionMaterial(String resName, String typeSub) {
		boolean inputAccepted = false;

		/* Generate a random number with a fixed size of 32 bytes */
		SecureRandom random = new SecureRandom();
		resRegRandom = new byte[Constants.randomNumberSize];
		random.nextBytes(resRegRandom); // Fill the array with random bytes
		System.out.println("c = " + toHex(resRegRandom));

		/* Generate a timestamp */
		Date date = new Date();
		long regTimestamp = date.getTime();
		byte[] regTimestampBytes = longToByteArray(regTimestamp);

		/*
		 * Compute the key Kr = H(d*P_DAS||Tr) used to encrypt requested resource (It is
		 * done for privacy purposes)
		 */
		/* Elliptic curve multiplication */
		ECPoint secretPoint = publicKeyDAS.getQ().multiply(privateKey.getD());
		byte[] encodedSecretPoint = secretPoint.getEncoded(true);

		/* Concatenate the encoded secret point with the timestamp */
		byte[] secretTimestampConcat = concatByteArrays(encodedSecretPoint, regTimestampBytes); // Tr

		/* Do the sha256 of the secretTimestampConcat byte array */
		byte[] Kr = sha256(secretTimestampConcat);

		// byte[] Kr = {'a','b','c'};

		//System.out.println("Symmetric key Kr(toHex): " + toHex(Kr));
		//System.out.println("Symmetric key Kr: " + Kr);

		/*
		 * Get resource name and subscription type from the user (it will be change with
		 * a GUI)
		 */
		/*
		 * while(!inputAccepted) { Scanner input = new Scanner(System.in);
		 * System.out.print("Enter the resource that you want to retrieve (" +
		 * Constants.TEMPERATURE + "/" + Constants.HUMIDITY + "/" + Constants.LOUDNESS +
		 * "): "); resName = input.nextLine();
		 * System.out.print("Enter the type of subscription that you prefer [" +
		 * Constants.SILVER + "(" + Constants.SILVER_PERIOD + "-" +
		 * Constants.SILVER_COST + " euro)/" + Constants.GOLD + "(" +
		 * Constants.GOLD_PERIOD + "-" + Constants.GOLD_COST + " euro)/" +
		 * Constants.PLATINUM + "(" + Constants.PLATINUM_PERIOD + "-" +
		 * Constants.PLATINUM_COST + " euro)]: "); typeSub = input.nextLine();
		 * if(!resName.equals(Constants.TEMPERATURE) &&
		 * !resName.equals(Constants.HUMIDITY) && !resName.equals(Constants.LOUDNESS)) {
		 * inputAccepted = false;
		 * System.out.println("Resource name provided is not valid"); }else
		 * if(!typeSub.equals(Constants.SILVER) && !typeSub.equals(Constants.GOLD) &&
		 * !typeSub.equals(Constants.PLATINUM)) { inputAccepted = false;
		 * System.out.println("Type of subscritpion provided is not valid"); }else {
		 * inputAccepted = true; input.close(); } }
		 */

		/* Create the cleartext to encrypt from the information provided by the user */
		String sepSymb = "||";
		byte[] resNameBytes = hexStringToByteArray(toHex(resName)); // Rn = resNameBytes
		byte[] typeSubBytes = hexStringToByteArray(toHex(typeSub)); // Tr = typeSubBytes
		// Add separation symbol to resource name
		byte[] cleartext = concatByteArrays(resNameBytes, hexStringToByteArray(toHex(sepSymb))); // cleartext = Sub chua
																									// ma hoa
		// Add type of subscription
		cleartext = concatByteArrays(cleartext, typeSubBytes);

		cleartext = concatByteArrays(cleartext, hexStringToByteArray(toHex(sepSymb)));
		// Add random number
		cleartext = concatByteArrays(cleartext, resRegRandom); // c= resRegRandom
		cleartext = concatByteArrays(cleartext, hexStringToByteArray(toHex(sepSymb)));
		// Add IDu
		cleartext = concatByteArrays(cleartext, hexStringToByteArray(toHex(Constants.clientID)));
		cleartext = concatByteArrays(cleartext, hexStringToByteArray(toHex(sepSymb)));

		// Add Kr
		String KrString = toHex(Kr);
		cleartext = concatByteArrays(cleartext, hexStringToByteArray(toHex(KrString)));

		System.out.println("cleartext: " + toHex(cleartext)); // Sub khi chua ma hoa

		/* tao diem Z */

		// Get domain parameters for example curve secp256r1
		X9ECParameters ecp = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(), ecp.getG(), ecp.getN(), ecp.getH(),
				ecp.getSeed());
		/* Generate a random number with a fixed size of 32 bytes */
		resRegRandomZ = new byte[Constants.randomNumberSize]; // resRegRandomZ= z
		random.nextBytes(resRegRandomZ); // Fill the array with random bytes
		System.out.println("z = " + toHex(resRegRandomZ));

		/* Elliptic curve multiplication using the random number */
		ECPoint pointZ = domainParams.getG().multiply(new BigInteger(resRegRandomZ));
		byte[] encodedZ = pointZ.getEncoded(true); // encodedZ= Z

		/* Kz=H(z*PDAS||Tr) */

		/* Elliptic curve multiplication */
		ECPoint secretPointZ = publicKeyDAS.getQ().multiply(new BigInteger(resRegRandomZ));
		byte[] encodedSecretPointZ = secretPointZ.getEncoded(true);

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

		// return toHex(regTimestampBytes) + "|" + toHex(ciphertext) + "|" +
		// toHex(nonce);
		return toHex(regTimestampBytes) + "|" + toHex(ciphertext) + "|" + toHex(nonce) + "|" + toHex(encodedZ);
	}

	public static String createAuthIdentity() {
		byte[] clientIDBytes = hexStringToByteArray(Constants.clientID);
		// Concatenate the identity with the random number generated during resource
		// registration
		byte[] IDresRegRandomConcat = concatByteArrays(clientIDBytes, resRegRandom);
		// Do the sha256 of the concatenation
		byte[] Qu = sha256(IDresRegRandomConcat);
		// add
		System.out.println("Qu= " + toHex(Qu));
		return toHex(Qu);
	}

	public static String generateSymmetricSessionKey(String Ts) {
		// Compute the symmetric session key SKsession = H(du*Pdas||Ts)
		// Elliptic curve multiplication
		ECPoint secretPoint = publicKeyDAS.getQ().multiply(privateKey.getD());
		byte[] encodedSecretPoint = secretPoint.getEncoded(true);
		// Concatenate encoded secret point with the received timestamp
		byte[] secretTimestampEncoded = concatByteArrays(encodedSecretPoint, hexStringToByteArray(Ts));
		// Do sha256 to obtain the symmetric key
		symmetricSessionKey = sha256(secretTimestampEncoded);
		System.out.println("Symmetric session key: " + toHex(symmetricSessionKey));
		return toHex(symmetricSessionKey);
	}

	public static String getSymmetricSessionKey() {
		return toHex(symmetricSessionKey);
	}
}
