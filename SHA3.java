/**
 * SHA3.java
 * 
 * TCSS 487 - Winter 2019
 * Programming Assignment
 * 
 * SHA-3 functions derived from NIST SP 800-185 and 
 * inspired by Markku-Juhani O. Saarinen's implementation in C
 * https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * 
 * @version March 08, 2019
 */
public class SHA3 {
	
	private byte[] b = new byte[200];       // 8-bit bytes
	private int pt, rsiz, mdlen;            // these don't overflow

	private final int KECCAKF_ROUNDS = 24;
	private final int SHAKE256 = 32;
	
	private  long ROTL64(long x, int y) {
		return (x << y) | (x >>> (64 - y));
	}
	
    private final long[] keccakf_rndc = {
		0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
		0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
		0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
		0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
		0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
		0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
		0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
		0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
	};

    private final int[] keccakf_rotc = {
		1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
		27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
	};

    private  final int[] keccakf_piln = {
		10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
		15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
	};

    private void sha3_keccakf(byte[] v) {
    	long[] bc = new long[5];
    	long[] st = new long[25];
    	long t;
    	
    	// endianess conversion. this is redundant on little-endian targets
    	for (int i = 0, j = 0; i < 25; i++, j += 8) {
			st[i] = (((long)v[j + 0] & 0xFFL)      ) | (((long)v[j + 1] & 0xFFL) <<  8) |
					(((long)v[j + 2] & 0xFFL) << 16) | (((long)v[j + 3] & 0xFFL) << 24) |
					(((long)v[j + 4] & 0xFFL) << 32) | (((long)v[j + 5] & 0xFFL) << 40) |
					(((long)v[j + 6] & 0xFFL) << 48) | (((long)v[j + 7] & 0xFFL) << 56);
        }
    	
        // actual iteration
    	for (int r = 0; r < KECCAKF_ROUNDS; r++) {
    		
    		// Theta
            for (int i = 0; i < 5; i++) {
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            }
            
            for (int i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5)
                    st[j + i] ^= t;
            }
            
            // Rho Pi
            t = st[1];
            for (int i = 0; i < 24; i++) {
                int j = keccakf_piln[i];
                bc[0] = st[j];
                st[j] = ROTL64(t, keccakf_rotc[i]);
                t = bc[0];
            }

            //  Chi
            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++)
                    bc[i] = st[j + i];
                for (int i = 0; i < 5; i++)
                    st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }

            //  Iota
            st[0] ^= keccakf_rndc[r]; 
    	}
    	
        // endianess conversion. this is redundant on little-endian targets
        for (int i = 0, j = 0; i < 25; i++, j+=8) {
            t = st[i];
            v[0 + j] = (byte) (t & 0xFF);
            v[1 + j] = (byte) ((t >> 8) & 0xFF);
            v[2 + j] = (byte) ((t >> 16) & 0xFF);
            v[3 + j] = (byte) ((t >> 24) & 0xFF);
            v[4 + j] = (byte) ((t >> 32) & 0xFF);
            v[5 + j] = (byte) ((t >> 40) & 0xFF);
            v[6 + j] = (byte) ((t >> 48) & 0xFF);
            v[7 + j] = (byte) ((t >> 56) & 0xFF);
        }
    }
    
    /**
     *  Initialize the context for SHA3 
     */
    public void sha3_init(int mdlen) {
    	for (int i = 0; i < 200; i++) {
    		this.b[0] = (byte) 0;
    	}
    	this.mdlen = mdlen;
    	this.rsiz = 200 - 2 * mdlen;
    	this.pt = 0;
    }
    
    /** 
     * Update state with more data
     */
    public void sha3_update(byte[] data, int len) {
    	int j = this.pt;
    	for (int i = 0; i < len; i++) {
    		this.b[j++] ^= data[i];
    		if (j >= this.rsiz) {
    			sha3_keccakf(b);
    			j = 0;
    		}
    	}
    	this.pt = j;
    }
    
    public void shake_xof(boolean iscSHAKE) {

        if (iscSHAKE) { 
        	this.b[this.pt] ^= 0x04; // cSHAKE is 00
        } else {
        	this.b[this.pt] ^= 0x1F; // SHAKE is 1111
        }     
        this.b[this.rsiz-1] ^= (byte) 0x80;
        sha3_keccakf(this.b);
        this.pt = 0;
    }
    
    public void shake_out(byte[] out, int len) {
		int j = this.pt;
		for (int i = 0; i < len; i++) {
			if (j >= this.rsiz) {
				sha3_keccakf(b);
				j = 0;
			}
			out[i] = this.b[j++];
		}
		this.pt = j;
	}
    
	/**
	 * Concatenate 2 byte arrays derived from
	 * https://stackoverflow.com/questions/5513152/easy-way-to-concatenate-two-byte-arrays
	 * 
	 * @param a is the first bit string 
	 * @param b is the second bit string
	 * @return result concatenated bit string
	 */
    public static byte[] concat(byte[] a, byte[] b) {
		byte[] concat = new byte[a.length + b.length];
		System.arraycopy(a, 0, concat, 0, a.length);
		System.arraycopy(b, 0, concat, a.length, b.length);
		return concat;
	}
	
	/**
	 * Helper method to get log base 2 of integer n
	 * @param n is the integer 
	 * @return log base 2 of n
	 */
	public static double log2(int n)	{
	    return (Math.log(n) / Math.log(2));
	}
	
	/**
	 * Left encoding
	 * 
	 * @param x is the integer to be left encoded
	 * @return left encode of x
	 */
	private static byte[] left_encode(int x) {
		if (x < 0) x = 0;
		if (x >= Math.pow(2, 2040)) x = (int) Math.pow(2, 2040) - 1;
		
		// n be the smallest positive int for 2^(8n) > x
		int n = (int) (log2(x) / 8) ;
		if (Math.pow(2, 8*n) <= x) { // Round up n
			n++;
		}
		if (x == 0) n = 1; 
		
		byte[] O = new byte[n + 1];
		for (int i = 1; i <= n; i++) {
			O[i] = (byte) (x >> (8 * (i - 1)));
		}
		
		O[0] = (byte) n;
		
		return O;
	}
	
	/**
	 * Right encoding
	 * 
	 * @param x is the integer to be right encoded
	 * @return right encode of x
	 */
	private static byte[] right_encode(int x) {
		if (x < 0) x = 0;
		if (x >= Math.pow(2, 2040)) x = (int) Math.pow(2, 2040) - 1;
		
		int n = (int) (log2(x) / 8) ;
		if (Math.pow(2, 8*n) <= x) { // Round up n
			n++;
		}
		
		if (x == 0) n = 1; 
		
		byte[] O = new byte[n + 1];
		for (int i = 1; i <= n; i++) {
			O[i] = (byte) (x >> (8 * (i - 1)));
		}
		
		O[n] = (byte) n;
		
		return O;
	}
	
	/**
	 * Encode bit strings in a way that may be parsed unambiguously 
	 * from the beginning of the string S. 
	 * 
	 * @param S is the string needed to encode
	 * @return left_encode(len(S)) || S
	 */
	private static byte[] encode_string(byte[] S) {
		if (S == null || S.length == 0) {
			return left_encode(0);
		} else {			
			return concat(left_encode(S.length << 3), S);
		}  
	}
	
	/**
	 * Prepends an encoding of int w to input string X, then padding result with 0s 
	 * until it is a byte string whose length in bytes is a multiple of w 
	 * 
	 * @param X is the string needed to pad
	 * @param w is the integer 
	 * @return
	 */	
    private static byte[] bytepad(byte[] X, int w) {
    	if (w < 0) w = 0;
		byte[] z = concat(left_encode(w), X);
		int padLength = w - (z.length % w);
		return concat(z, intToByteArray(padLength));
    }
    
    /**
     * Convert int to byte array
     * https://stackoverflow.com/questions/2183240/java-integer-to-byte-array
     * 
     * @param value is the int need to be converted
     * @return byte array of given int
     */
    private static byte[] intToByteArray(int value) {
        return new byte[] {
                (byte)(value >>> 24),
                (byte)(value >>> 16),
                (byte)(value >>> 8),
                (byte)value};
    }
	
	/**
	 * 
	 * @param N is a function-name bit string 
	 * @param S is a customization bit string
	 */
	private void cSHAKE256Helper(byte[] N, byte[] S) {
		sha3_init(SHAKE256);
		byte[] bytepad= bytepad(concat(encode_string(N), encode_string(S)), 136);
		sha3_update(bytepad, bytepad.length);
	}
	
	/**
	 * Function cSHAKE256
	 * 
	 * @param X is the main input bit string of any length
	 * @param L is an integer representing the requested output length in bits
	 * @param N is a function-name bit string 
	 * @param S is a customization bit string
	 * @return either SHAKE or KECCAK
	 */
	private static byte[] cSHAKE256(byte[] X, int L, byte[] N, byte[] S) {
		SHA3 sha = new SHA3();
		boolean cSHAKE = false;
		byte[] result = new byte[L >>> 3];
		if (N.length != 0 && S.length != 0) { // use cSHAKE
			sha.cSHAKE256Helper(N, S);
			cSHAKE = true;
		}
		sha.sha3_update(X, X.length);
		sha.shake_xof(cSHAKE);
		sha.shake_out(result, L >>> 3);
		return result;
	}
	
	/**
	 * Function KMACXOF256
	 * 
	 * @param K is a key bit string of any length
	 * @param X is the main input bit string
	 * @param L is an integer representing the requested output length in bits 
	 * @param S is an optional customization bit string
	 * @return cSHAKE256
	 */
	public static byte[] KMACXOF256(byte[] K, byte[] X, int L, byte[] S) {
		byte[] newX = concat(concat(bytepad(encode_string(K),136), X), right_encode(0));
		return cSHAKE256(newX, L, "KMAC".getBytes(), S);
	}
	
}
