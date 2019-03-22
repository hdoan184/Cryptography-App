/**
 * SymmetricCryptography.java
 * 
 * TCSS 487 - Winter 2019
 * Programming Assignment 
 * 
 * Program to encrypt/decrypt symmetrically under a given passphrase.
 * 
 * @author Hien Doan
 * @version March 08, 2019
 */
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class SymmetricCryptogram {
	
	// Instance fields
    private byte[] z;
    private byte[] c;
    private byte[] t;
    
    // Constructions
    public SymmetricCryptogram() { }
    
    public SymmetricCryptogram(byte[] theZ, byte[] theC, byte[] theT) {
    	this.z = theZ;
    	this.c = theC;
    	this.t = theT;
    }
    
    // Getters
    public byte[] getZ() {  return z;  }
    public byte[] getC() {  return c;  }
    public byte[] getT() {	return t;  }
    
    /** 
     * Encrypting a byte array m symmetrically under the passphrase pw
     * 
     * @param m is the byte array needed to encrypt
     * @param pw is the passphrase
     * @return SymmetricCryptogram(z, c, t)
     */
	public static SymmetricCryptogram encrypt(byte[] m, byte[] pw) {

		// z <- Random(512)
		SecureRandom random = new SecureRandom();
		byte[] z = new byte[512];
		random.nextBytes(z);
		
		// (ke || ka) <- KMACXOF256(z || pw, "", 1024, "S")
		byte[] zpw = SHA3.concat(z, pw);     // z || pw
		byte[] keka = SHA3.KMACXOF256(zpw, "".getBytes(), 1024, "S".getBytes());
		
		// c <- KMACXOF256(ke, "", |m|, "SKE") xor m
		byte[] ke = Arrays.copyOfRange(keka, 0, keka.length/2);
		byte[] c = SHA3.KMACXOF256(ke, "".getBytes(), m.length, "SKE".getBytes());
		// Change to BigInteger to xor
		BigInteger cBigInt = new BigInteger(c);
		BigInteger mBigInt = new BigInteger(m);
		cBigInt = cBigInt.xor(mBigInt);    
		c = cBigInt.toByteArray();         // convert back to byte[]
		
		// t <- KMACXOF256(ka, m, 512, "SKA")
		byte[] ka = Arrays.copyOfRange(keka, keka.length/2, keka.length);
		byte[] t = SHA3.KMACXOF256(ka, pw, 512, "SKA".getBytes());
		
		// symmetric cryptogram: (z, c, t)
		return new SymmetricCryptogram(z, c, t);
	}
	
	/**
	 * Decrypting a symmetric cryptogram (z, c, t) under the passphrase pw
	 * 
	 * @param sc is the SymmetricCryptogram
	 * @param pw is the passphrase
	 */
	public static byte[] decrypt(SymmetricCryptogram sc, byte[] pw) {
		byte[] z = sc.z;
		byte[] c = sc.c;
		byte[] t = sc.t;
		byte[] result = null;

		// (ke || ka) <- KMACXOF256(z || pw, "", 1024, "S")
		byte[] zpw = SHA3.concat(z, pw);
		byte[] keka = SHA3.KMACXOF256(zpw, "".getBytes(), 1024, "S".getBytes());
		
		// m <- KMACXOF256(ke, "", |c|, "SKE") xor c
		byte[] ke = Arrays.copyOfRange(keka, 0, keka.length/2);
		byte[] m = SHA3.KMACXOF256(ke, "".getBytes(), c.length, "SKE".getBytes());
		// Change to BigInteger to xor
		BigInteger mBigInt = new BigInteger(m);
		BigInteger cBigInt = new BigInteger(c);
		mBigInt = mBigInt.xor(cBigInt);    
		m = mBigInt.toByteArray();         // convert back to byte[]
		
		// t’ <- KMACXOF256(ka, m, 512, "SKA")
		byte[] ka = Arrays.copyOfRange(keka, keka.length/2, keka.length);
		byte[] tPrime = SHA3.KMACXOF256(ka, m, 512, "SKA".getBytes());
		
		// accept if, and only if, t’ = t
		if (Arrays.equals(t, tPrime)) {
			result = m;
		} 

		return m;
	}

}
