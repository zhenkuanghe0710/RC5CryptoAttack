import edu.rit.util.Hex;
import edu.rit.util.Packing;

/**
 * Class RC5 is a Block Cipher that use RC5 algorithm and implements BlockCipher
 * interface.
 * <P>
 * <I>Plaintext</I> = Plain text input <BR>
 * <I>Ciphertext</I> = Plain text input <BR>
 * <I>Key</I> = Cipher Key
 */

public class RC5 implements BlockCipher {

	private int round; // Number of rounds
	private int S[]; // Key S array
	private int t; // (round + 1) * 2
	private int w = Integer.SIZE; // Word size (32bits)
	private int b = keySize(); // Key size(16bytes)
	private int u = w / 8;
	private int c = Math.max(b, 1) / u;

	private int P = 0xb7e15163; // P32
	private int Q = 0x9e3779b9; // Q32

	/**
	 * Return the block size
	 * 
	 * @return Integer value of block size.
	 */
	public int blockSize() {

		return 8;
	}

	/**
	 * Return the key size
	 * 
	 * @return Integer value of key size.
	 */
	public int keySize() {

		return 16;
	}

	/**
	 * Set the number of rounds.
	 * 
	 * @param Integer
	 *            Number of rounds.
	 */
	public void setRounds(int R) {

		this.round = R;
		this.t = (R + 1) * 2;
	}

	/**
	 * Set the key array S[].
	 * 
	 * @param byte[] Cipher key.
	 */
	public void setKey(byte[] key) {

		// Converting the Secret Key from Bytes to Words
		// Need to use LittleEndian type
		int K[] = { Packing.packIntLittleEndian(key, 0),
				Packing.packIntLittleEndian(key, 4),
				Packing.packIntLittleEndian(key, 8),
				Packing.packIntLittleEndian(key, 12) };

		// Initializing the Array S
		S = new int[t];
		S[0] = P;
		for (int m = 1; m < t; m++) {
			S[m] = S[m - 1] + Q;
		}

		// Mixing in the Secret Key
		int i = 0;
		int j = 0;
		int X = 0;
		int Y = 0;

		for (int m = 0; m < (Math.max(t, c) * 3); m++) {
			// Need to follow the order above
			S[i] = rotateLeft(S[i] + X + Y, 3);
			X = S[i];
			K[j] = rotateLeft(K[j] + X + Y, X + Y);
			Y = K[j];

			i = (i + 1) % t;
			j = (j + 1) % c;
		}
	}

	/**
	 * Do the digit left shift
	 * 
	 * @param Integer
	 *            Value of A which want to rotate
	 * @param Integer
	 *            Value of B which need to rotate
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
	 * @param Integer
	 *            Value of A which want to rotate
	 * @param Integer
	 *            Value of B which need to rotate
	 * 
	 * @return Integer value of after A right shift with B.
	 */
	public int rotateRight(int A, int B) {
		return (A >>> (B & (w - 1))) | (A << (w - (B & (w - 1))));
	}

	/**
	 * Encrypt function
	 */
	public void encrypt(byte[] text) {
		// Convert the text from bytes to words
		int pt1 = Packing.packIntLittleEndian(text, 0);
		int pt2 = Packing.packIntLittleEndian(text, 4);

		// Initialize the input A and B
		int A = pt1 + S[0];
		int B = pt2 + S[1];

		// Do rounds of encryption
		for (int i = 1; i <= round; i++) {
			A = rotateLeft(A ^ B, B) + S[i * 2];
			B = rotateLeft(B ^ A, A) + S[i * 2 + 1];
		}

		// Because of the LittleEndian order
		// A need to place behind B
		long ct1 = (long) B << 32;
		long ct2 = (long) A & 0xFFFFFFFFL;
		long data = ct1 | ct2;

		// Need to use LittleEndian order
		Packing.unpackLongLittleEndian(data, text, 0);
	}

	/**
	 * Decrypt function
	 */
	public void decrypt(byte[] text) {
		// Convert the text from bytes to words
		int ct1 = Packing.packIntLittleEndian(text, 0);
		int ct2 = Packing.packIntLittleEndian(text, 4);

		// Initialize the input A and B
		int A = ct1;
		int B = ct2;

		// Do rounds of decryption
		for (int i = round; i > 0; i--) {
			B = rotateRight(B - S[i * 2 + 1], A) ^ A;
			A = rotateRight(A - S[i * 2], B) ^ B;
		}

		// Because of the LittleEndian order
		// A need to place behind B
		long pt1 = (long) (A - S[0]) & 0xFFFFFFFFL;
		long pt2 = (long) (B - S[1]) << 32;
		long data = pt1 | pt2;

		// Need to use LittleEndian order
		Packing.unpackLongLittleEndian(data, text, 0);
	}

	/**
	 * Get the S array
	 * 
	 * @return Integer[] value of after A right shift with B.
	 */
	public int[] getS() {
		return S;
	}

	/**
	 * Main method of the block cipher. Run the block cipher algorithm with the
	 * input(plaintext/ciphertext) and key to get the
	 * output(ciphertext/plaintext)
	 */
	public static void main(String[] args) {

		RC5 cipher = new RC5();

		if (args.length != 4)
			usage();

		else {
			int type = Integer.valueOf(args[0]);

			if (type == 1) {
				byte[] plaintext = Hex.toByteArray(args[1]);
				byte[] key = Hex.toByteArray(args[2]);

				// Encrypt (only use plaintext & key)
				byte[] ciphertext = (byte[]) plaintext.clone();
				cipher.setRounds(Integer.valueOf(args[3])); // Set rounds
				cipher.setKey(key); // Set key
				cipher.encrypt(ciphertext); // Encryption

				System.out.printf("PlainText: %s%nKey: %s%nCipherText:%s%n",
						Hex.toString(plaintext), Hex.toString(key),
						Hex.toString(ciphertext));
			} else if (type == 2) {
				byte[] ciphertext = Hex.toByteArray(args[1]);
				byte[] key = Hex.toByteArray(args[2]);

				// Decrypt (only use ciphertext & key)
				byte[] plaintext = (byte[]) ciphertext.clone();
				cipher.setRounds(Integer.valueOf(args[3]));
				cipher.setKey(key); // Set key
				cipher.decrypt(plaintext); // Decryption

				System.out.printf("CipherText: %s%nKey: %s%nPlainText:%s%n",
						Hex.toString(ciphertext), Hex.toString(key),
						Hex.toString(plaintext));

			} else
				usage();
		}
	}

	private static void usage() {
		System.err
				.println("Usage: java RC5 <Type> <PlainText/CipherText> <Key> <Round>");
		System.err
				.println("<Type> = 1 Charater String. 1 -- Encryption 2 -- Decryption");
		System.err
				.println("<PlainText/CipherText> = 16 Charater Hex String. Type = 1 input PlainText; Type = 2 input CipherText");
		System.err.println("<Key> = 32 Charater Hex Key String");
		System.err.println("<Round> = Number of Rounds");
		System.exit(1);
	}
}
