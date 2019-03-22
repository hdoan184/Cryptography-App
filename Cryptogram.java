/**
 * Cryptogram.java
 * 
 * TCSS 487 - Winter 2019
 * Programming Assignment
 * 
 * Program to encrypt/decrypt under the (Schnorr/ECDHIES) public key V.
 * 
 * @author Hien Doan
 * @version March 09, 2019
 */
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class Cryptogram {
	// Instance fields
    private ECPoint Z;
    private byte[] c;
    private byte[] t;
    
    // Constructions
    public Cryptogram() { }
    
    public Cryptogram(ECPoint theZ, byte[] theC, byte[] theT) {
    	this.Z = theZ;
    	this.c = theC;
    	this.t = theT;
    }
    
    // Getters
    public ECPoint getZ() {  return Z;  }
    public byte[] getC()  {  return c;  }
    public byte[] getT()  {	 return t;  }
    
    /**
     * Generating a (Schnorr/ECDHIES) key pair (s, V) from a passphrase pw.
     * 
     * @param pw is the passphrasw
     * @return key pair
     */
    public static ECPoint generatePublicKey(String pw) {
    	
    	// s <- KMACXOF256(pw, "", 512, "K")
    	byte[] s = SHA3.KMACXOF256(pw.getBytes(), "".getBytes(), 512, "K".getBytes());
    			
    	// s <- 4s
    	BigInteger sBigInt = new BigInteger(s).multiply(new BigInteger("4"));
    	s = sBigInt.toByteArray();
    			
    	// V <- s*G
    	int exp = (int) SHA3.log2(sBigInt.intValue());
    	String str = Integer.toUnsignedString(exp);    	
        char[] array = str.toCharArray();
        ECPoint V = ECPoint.G;
    	for (int i = 0; i < array.length; i++) {
    		V = ECPoint.add(V, V);
    		if (array[i] == '1') {
    			V = ECPoint.add(V, ECPoint.G);
    		}
    	}
    	return V;
    }

    /** 
     * Encrypting a byte array m under public key V
     * 
     * @param m is the byte array needed to encrypt
     * @param V is the public key
     * @return Cryptogram(Z, c, t)
     */
	public static Cryptogram encrypt(byte[] m, ECPoint V) {
		
		// z <- Random(512)
		SecureRandom random = new SecureRandom();
		byte[] k = new byte[512];
		random.nextBytes(k);
		// k <- 4k
		BigInteger kBigInt = new BigInteger(k).multiply(new BigInteger("4"));
		k = kBigInt.toByteArray();
		
		// W <- k*V
		int exp = (int) SHA3.log2(kBigInt.intValue());
    	String str = Integer.toUnsignedString(exp);    	
        char[] array = str.toCharArray();
        ECPoint W = V;
    	for (int i = 0; i < array.length; i++) {
    		W = ECPoint.add(W, W);
    		if (array[i] == '1') {
    			W = ECPoint.add(W, V);
    		}
    	}
    	
    	// Z <- k*G
    	ECPoint Z = ECPoint.G;
    	for (int i = 0; i < array.length; i++) {
    		Z = ECPoint.add(Z, Z);
    		if (array[i] == '1') {
    			Z = ECPoint.add(V, ECPoint.G);
    		}
    	}
	
		// (ke || ka) <- KMACXOF256(Wx, "", 1024, "P")
		byte[] keka = SHA3.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
		
		// c <- KMACXOF256(ke, "", |m|, "PKE") xor m
		byte[] ke = Arrays.copyOfRange(keka, 0, keka.length/2);
		byte[] c = SHA3.KMACXOF256(ke, "".getBytes(), m.length, "PKE".getBytes());
		// Change to BigInteger to xor
		BigInteger cBigInt = new BigInteger(c);
		BigInteger mBigInt = new BigInteger(m);
		cBigInt = cBigInt.xor(mBigInt);    
		c = cBigInt.toByteArray();         // convert back to byte[]
		
		// t <- KMACXOF256(ka, m, 512, "PKA")
		byte[] ka = Arrays.copyOfRange(keka, keka.length/2, keka.length);
		byte[] t = SHA3.KMACXOF256(ka, m, 512, "PKA".getBytes());
		
		// Cryptogram: (z, c, t)
		return new Cryptogram(Z, c, t);
	}
	
	/**
	 * Decrypting a cryptogram (Z, c, t) under the passphrase pw.
	 * 
	 * @param c is the Cryptogram
	 * @param pw is the passphrase
	 */
	public static byte[] decrypt(Cryptogram crypt, byte[] pw) {
		ECPoint Z = crypt.Z;
		byte[] c = crypt.c;
		byte[] t = crypt.t;
		byte[] result = null;
		
		// s <- KMACXOF256(pw, "", 512, "K")
		byte[] s = SHA3.KMACXOF256(pw, "".getBytes(), 512, "K".getBytes());
		// s <- 4s
		BigInteger sBigInt = new BigInteger(s).multiply(new BigInteger("4"));
		s = sBigInt.toByteArray();
		
		// W <- s*Z
		ECPoint W = Z;
		int exp = (int) SHA3.log2(sBigInt.intValue());
    	String str = Integer.toUnsignedString(exp);    	
        char[] array = str.toCharArray();
		
		for (int i = 0; i < array.length; i++) {
    		W = ECPoint.add(W, W);
    		if (array[i] == '1') {
    			W = ECPoint.add(W, Z);
    		}
    	}

		// (ke || ka) <- KMACXOF256(Wx, "", 1024, "P")
		byte[] keka = SHA3.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
		
		// m <- KMACXOF256(ke, "", |c|, "PKE") xor c
		byte[] ke = Arrays.copyOfRange(keka, 0, keka.length/2);
		byte[] m = SHA3.KMACXOF256(ke, "".getBytes(), c.length, "PKE".getBytes());
		// Change to BigInteger to xor
		BigInteger mBigInt = new BigInteger(m);
		BigInteger cBigInt = new BigInteger(c);
		mBigInt = mBigInt.xor(cBigInt);    
		m = mBigInt.toByteArray();         // convert back to byte[]
		
		// t’ <- KMACXOF256(ka, m, 512, "PKA")
		byte[] ka = Arrays.copyOfRange(keka, keka.length/2, keka.length);
		byte[] tPrime = SHA3.KMACXOF256(ka, m, 512, "PKA".getBytes());
		
		// accept if, and only if, t’ = t
		if (Arrays.equals(t, tPrime)) {
			result = m;
		} 

		return m;
	}
}
