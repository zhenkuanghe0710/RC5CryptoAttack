import java.util.HashMap;
import java.util.Random;
import edu.rit.util.Hex;
import edu.rit.util.Packing;

/**
 * Class AttackRC5 is a attack program that attack one round RC5 algorithm
 * <P>
 * <I>Key</I> = Cipher Key
 */
public class AttackRC5 {

	private final int w = Integer.SIZE; // Word size (32bits)

	/**
	 * Do the digit left shift
	 * 
	 * @return Integer value of after A left shift with B.
	 */
	public int rotateLeft(int A, int B) {
		// B is 32bits integer
		// need to mod w(32) to make sure the range of digit shift
		return (A << (B & (w - 1))) | (A >>> (w - (B & (w - 1))));
	}

	/**
	 * Do the digit right shift
	 * 
	 * @return Integer value of after A right shift with B.
	 */
	public int rotateRight(int A, int B) {
		return (A >>> (B & (w - 1))) | (A << (w - (B & (w - 1))));
	}

	/**
	 * Do the half round decryption of B
	 * 
	 * @param byte[] Test plaintext
	 * @param byte[] Test ciphertext
	 * @param Integer
	 *            Test value of S3
	 * 
	 * @return Integer the value after half round decryption of B
	 */
	public int decryptB(byte[] plaintext, byte[] ciphertext, int S3) {
		// Convert the text from bytes to words
		int A1 = Packing.packIntLittleEndian(ciphertext, 0);
		int B1 = Packing.packIntLittleEndian(ciphertext, 4);

		int B0 = Packing.packIntLittleEndian(plaintext, 4);

		int Bmid = rotateRight(B1 - S3, A1) ^ A1;

		int S1 = Bmid - B0;

		return S1;
	}

	/**
	 * Do the half round decryption of A
	 * 
	 * @param byte[] Test plaintext
	 * @param byte[] Test ciphertext
	 * @param Integer
	 *            Certain value of S3
	 * @param Integer
	 *            Test value of S2
	 * 
	 * @return Integer the value after half round decryption of A
	 */
	public int decryptA(byte[] plaintext, byte[] ciphertext, int S3, int S2) {
		// Convert the text from bytes to words
		int A1 = Packing.packIntLittleEndian(ciphertext, 0);
		int B1 = Packing.packIntLittleEndian(ciphertext, 4);

		int A0 = Packing.packIntLittleEndian(plaintext, 0);

		int Bmid = rotateRight(B1 - S3, A1) ^ A1;
		int Amid = rotateRight(A1 - S2, Bmid) ^ Bmid;

		int S0 = Amid - A0;

		return S0;
	}

	/**
	 * Main method of the attack program. Run the program with the input(key) to
	 * get the output(S0, S1, S2, S3)
	 */
	public static void main(String[] args) {

		AttackRC5 attack = new AttackRC5();

		if (args.length != 1)
			usage();
		else {
			byte[] key = Hex.toByteArray(args[0]);

			Generator oracle = new Generator(key);
			int[] S = oracle.GenerateS();

			// Display the key and correct S0-S3
			System.out.printf("KEY -- %s (Shhhhh..)%n", Hex.toString(key));
			System.out.printf("S0  -- %s%nS1  -- %s%nS2  -- %s%nS3  -- %s%n%n",
					Integer.toBinaryString(S[0]), Integer.toBinaryString(S[1]),
					Integer.toBinaryString(S[2]), Integer.toBinaryString(S[3]));

			// Generate the first pair of plaintext and ciphertext
			byte[] plaintext1 = oracle.GeneratePlaintext();
			byte[] ciphertext1 = oracle.GenerateCiphertext(plaintext1);

			System.out.printf("PT1 -- %s%nCT1 -- %s%n%n",
					Hex.toString(plaintext1), Hex.toString(ciphertext1));

			// Generate the second pair of plaintext and ciphertext
			byte[] plaintext2 = oracle.GeneratePlaintext();
			byte[] ciphertext2 = oracle.GenerateCiphertext(plaintext2);

			System.out.printf("PT2 -- %s%nCT2 -- %s%n%n",
					Hex.toString(plaintext2), Hex.toString(ciphertext2));

			// Generate the third pair of plaintext and ciphertext
			byte[] plaintext3 = oracle.GeneratePlaintext();
			byte[] ciphertext3 = oracle.GenerateCiphertext(plaintext3);

			System.out.printf("PT3 -- %s%nCT3 -- %s%n%n",
					Hex.toString(plaintext3), Hex.toString(ciphertext3));

			HashMap<Integer, Integer> S31pair = new HashMap<Integer, Integer>();

			// Begin to attack S3&S1 with first two pair PT&CT
			System.out.printf("Attack with PT1&CT1 and PT2&CT2%n%n");
			for (int S3 = Integer.MIN_VALUE; S3 < Integer.MAX_VALUE; S3++) {

				int S1i = attack.decryptB(plaintext1, ciphertext1, S3);
				int S1 = attack.decryptB(plaintext2, ciphertext2, S3);

				// If match both of PT&CT, keep those
				if (S1i == S1) {
					S31pair.put(S3, S1);
					System.out.printf("*S3*-- %s%n*S1*-- %s%n%n",
							Integer.toBinaryString(S3),
							Integer.toBinaryString(S1));
				}
			}

			int S3 = 0;
			int S1 = 0;

			// If only one pair, that's the correct result of S3&S1
			if (S31pair.size() == 1) {
				for (int s3 : S31pair.keySet()) {
					S3 = s3;
					S1 = S31pair.get(S3);
				}
			} else {
				// Begin to attack S3&S1 with the third pair PT&CT
				System.out.printf("Attack with PT3&CT3%n%n");

				for (int s3 : S31pair.keySet()) {
					int s1i = attack.decryptB(plaintext1, ciphertext1, s3);
					int s1 = attack.decryptB(plaintext3, ciphertext3, s3);

					// If match every PT&CT, keep those
					if (s1i == s1) {
						S3 = s3;
						S1 = s1;
						System.out.printf("*S3*-- %s%n*S1*-- %s%n%n",
								Integer.toBinaryString(S3),
								Integer.toBinaryString(S1));
					}
				}
			}

			System.out.printf("Session 1 DONE%n%n");

			HashMap<Integer, Integer> S20pair = new HashMap<Integer, Integer>();

			// Begin to attack S2&S0 with first two pair PT&CT
			System.out.printf("Attack with PT1&CT1 and PT2&CT2%n%n");
			for (int S2 = Integer.MIN_VALUE; S2 < Integer.MAX_VALUE; S2++) {
				int S0i = attack.decryptA(plaintext1, ciphertext1, S3, S2);
				int S0 = attack.decryptA(plaintext2, ciphertext2, S3, S2);

				// If match both of PT&CT, keep those
				if (S0i == S0) {
					S20pair.put(S2, S0);
					System.out.printf("*S2*-- %s%n*S0*-- %s%n%n",
							Integer.toBinaryString(S2),
							Integer.toBinaryString(S0));
				}
			}

			int S2 = 0;
			int S0 = 0;

			// If only one pair, that's the correct result of S2&S0
			if (S20pair.size() == 1) {
				for (int s2 : S20pair.keySet()) {
					S2 = s2;
					S0 = S20pair.get(S2);
				}
			} else {
				// Begin to attack S2&S0 with the third pair PT&CT
				System.out.printf("Attack with PT3&CT3%n%n");

				for (int s2 : S20pair.keySet()) {
					int s0i = attack.decryptA(plaintext1, ciphertext1, S3, s2);
					int s0 = attack.decryptA(plaintext3, ciphertext3, S3, s2);

					// If match every PT&CT, keep those
					if (s0i == s0) {
						S2 = s2;
						S0 = s0;
						System.out.printf("*S2*-- %s%n*S0*-- %s%n%n",
								Integer.toBinaryString(S2),
								Integer.toBinaryString(S0));
					}
				}
			}

			System.out.printf("Session 2 DONE%n%n");

			// Compare with the correct set of S
			if (S0 == S[0] && S1 == S[1] && S2 == S[2] && S3 == S[3]) {
				System.out.printf("Block Cipher BROKE!%n%n");
				System.out.printf(
						"*S0*-- %s%n*S1*-- %s%n*S2*-- %s%n*S3*-- %s%n%n",
						Integer.toBinaryString(S0), Integer.toBinaryString(S1),
						Integer.toBinaryString(S2), Integer.toBinaryString(S3));
			}
		}
	}

	private static void usage() {
		System.err.println("Usage: java AttackRC5 <Key>");
		System.err.println("<Key> = 32 Charater Hex Key String");
		System.exit(1);
	}
}

/**
 * Class Generator is used to generate the random plaintext and encrypt that to
 * get the ciphertext of one round RC5 algorithm
 * <P>
 * <I>Key</I> = Cipher Key
 */
class Generator {
	private Random prng = new Random();
	private RC5 cipher = new RC5();

	/**
	 * Constructor
	 */
	public Generator(byte[] key) {
		this.prng.setSeed(8080);
		this.cipher.setRounds(1);
		this.cipher.setKey(key);
	}

	/**
	 * Generate random plaintext
	 * 
	 * @return byte[] A random plaintext
	 */
	public byte[] GeneratePlaintext() {
		byte[] pt = Hex.toByteArray(Long.toHexString(prng.nextLong()));

		return pt;
	}

	/**
	 * Generate random ciphertext
	 * 
	 * @param byte[] Input plaintext
	 * 
	 * @return byte[] A random ciphertext
	 */
	public byte[] GenerateCiphertext(byte[] pt) {
		byte[] ct = (byte[]) pt.clone();
		cipher.encrypt(ct);

		return ct;
	}

	/**
	 * Get the correct S array
	 * 
	 * @return int[] The correct set of S
	 */
	public int[] GenerateS() {
		return cipher.getS();
	}
}
