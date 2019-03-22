import java.math.BigInteger;
import java.util.Arrays;

public class Signature {
	// Instance fields
    private byte[] h;
    private byte[] z;
    
    // Constructions
    public Signature() { }    
    public Signature(byte[] theH, byte[] theZ) {
    	this.h = theH;
    	this.z = theZ;
    }
    
    // Getters
    public byte[] getH()  {  return h;  }
    public byte[] getZ()  {	 return z;  }
    
    /** 
     * Generating a signature for a byte array m under the passphrase pw
     * 
     * @param m is the byte array needed to encrypt
     * @param pw is the passphrase
     * @return Signature(h, z)
     */
	public static Signature createSignature(byte[] m, byte[] pw) {

		// s <- KMACXOF256(pw, "", 512, "K")
		byte[] s = SHA3.KMACXOF256(pw, "".getBytes(), 512, "K".getBytes());
		// s <- 4s
		BigInteger sBigInt = new BigInteger(s).multiply(new BigInteger("4"));
    	s = sBigInt.toByteArray();
    	
		// k <- KMACXOF256(s, m, 512, "N") 
		byte[] k = SHA3.KMACXOF256(s, m, 512, "N".getBytes());
		// k <- 4k
		BigInteger kBigInt = new BigInteger(k).multiply(new BigInteger("4"));
		k = kBigInt.toByteArray();
		
		// U <- k*G
		int exp = (int) SHA3.log2(kBigInt.intValue());
    	String str = Integer.toUnsignedString(exp);    	
        char[] array = str.toCharArray();
    	
	    ECPoint U = ECPoint.G;
    	for (int i = 0; i < array.length; i++) {
    		U = ECPoint.add(U, U);
    		if (array[i] == '1') {
    			U = ECPoint.add(U, ECPoint.G);
    		}
    	}
		
		// h <- KMACXOF256(Ux, m, 512, "T");
		byte[] h = SHA3.KMACXOF256(U.getX().toByteArray(), m, 512, "T".getBytes());
		
		//  z <- (k – hs) mod r
		kBigInt = new BigInteger(k);
		sBigInt = new BigInteger(s);
		BigInteger hBigInt = new BigInteger(h);
		BigInteger zBigInt = (kBigInt.subtract(hBigInt.multiply(sBigInt))).mod(ECPoint.r);
		byte[] z = zBigInt.toByteArray();
		System.out.println(ECPoint.r);
		return new Signature(h, z);
	}
	
	/**
	 * Verifying a signature for a given byte array m under the public key V.
     *
	 * @param sig is the signature.
	 * @param V is the public key.
	 * @return either true or false;
	 */
	public static boolean verifySignature(Signature sig, byte[] m, ECPoint V) {
		
		boolean result = false;
		byte[] h = sig.h;
	    byte[] z = sig.z;

	    BigInteger hBigInt = new BigInteger(h).multiply(new BigInteger("4"));
	    BigInteger zBigInt = new BigInteger(z).multiply(new BigInteger("4"));
	    
		// U <- z*G + h*V
	    int exp1 = (int) SHA3.log2(hBigInt.intValue());
    	String hStr = Integer.toUnsignedString(exp1);    	
        char[] hArray = hStr.toCharArray();
    	
	    ECPoint U1 = ECPoint.G;
    	for (int i = 0; i < hArray.length; i++) {
    		U1 = ECPoint.add(U1, U1);
    		if (hArray[i] == '1') {
    			U1 = ECPoint.add(U1, ECPoint.G);
    		}
    	}
    	
	    int exp2 = (int) SHA3.log2(zBigInt.intValue());
    	String zStr = Integer.toUnsignedString(exp2);    	
        char[] zArray = zStr.toCharArray();
    	
	    ECPoint U2 = V;
    	for (int i = 0; i < hArray.length; i++) {
    		U2 = ECPoint.add(U2, U2);
    		if (zArray[i] == '1') {
    			U2 = ECPoint.add(U2, V);
    		}
    	}
    	
    	ECPoint U = ECPoint.add(U1, U2);
	    
		// accept if, and only if, KMACXOF256(Ux, m, 512, "T") = h
	    byte[] hPrime = SHA3. KMACXOF256(U.getX().toByteArray(), m, 512, "T".getBytes());
	    
	    if (Arrays.equals(h, hPrime)) {
			result = true;
		} 
	    System.out.println(h.length + " " + Arrays.toString(h));
	    System.out.println(hPrime.length + " " + Arrays.toString(hPrime));
		return result;
	}
    
}
