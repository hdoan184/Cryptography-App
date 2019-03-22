/**
 * ECPoint.java
 * 
 * TCSS 487 - Winter 2019
 * Programming Assignment
 * 
 * Represents a point on elliptic curve.
 * 
 * @author Hien Doan
 * @version March 09, 2019
 */
import java.math.BigInteger;

public class ECPoint {
	
	/** Global parameters */
	// Mersenne prime
	public static final BigInteger p = new BigInteger("2").pow(521).subtract(BigInteger.ONE); 
	// d = -376014
	public static final BigInteger d = new BigInteger("376014").negate();  
	// Point G with x = 18 and y even
	public static final ECPoint G = new ECPoint(new BigInteger("18"), new BigInteger("8"));   
	
	public static final BigInteger r = new BigInteger("2").pow(519).subtract(new BigInteger("337554763258501705789107630418782636071" + 
			                                                                                   "904961214051226618635150085779108655765"));
	
	/** Instance fields */
	private BigInteger x;  // x coordinate 
	private BigInteger y;  // y coordinate 
	
	/**
	 * Constructor for neutral element (0, 1)
	 */
	public ECPoint() {
		this.x = BigInteger.ZERO;
		this.y = BigInteger.ONE;
	}
	
	/**
	 * Constructor for a curve point from its x coordinate 
	 * and the least significant bit of y.
	 * 
	 * @param theX is x coordinate.
	 */
	public ECPoint(BigInteger theX) {
		this.x = theX;
		this.y = lsbYCoord(x);
	}
	
	/**
	 * Constructor for a curve point from its x and y coordinates.
	 * 
	 * @param theX is x coordinate.
	 * @param theY is y coordinate.
	 */
	public ECPoint(BigInteger theX, BigInteger theY) {
		this.x = theX;
		this.y = theY;
	}
	
	// Getters
	public BigInteger getX() { return this.x; }
	public BigInteger getY() { return this.y; }
	
 	/**
 	 * Get the least significant bit of y from x coordinate.
 	 * 
 	 * @param x is the x coordinate.
 	 */
 	public static BigInteger lsbYCoord(BigInteger x) {
 		// We have: x^2 + y^2 = 1 + dx^2y^2
 		// Solve for y: y = sqrt( (1-x^2)/(1-dx^2) )
 		BigInteger numerator = BigInteger.ONE.subtract(x.pow(2));
 		BigInteger denominator = BigInteger.ONE.subtract(d.multiply(x.pow(2)));
 		BigInteger ySquare = numerator.divide(denominator);
 		return sqrt(ySquare, p, false);
 	}
 	
 	/**
 	 * Add 2 points on the curve.
 	 * 
 	 * @param p1 is the 1st point on elliptic curve.
 	 * @param p2 is the 2nd point on elliptic curve.
 	 * @return addition of 2 points on the curve.
 	 */
 	public static ECPoint add(ECPoint p1, ECPoint p2) {
 		BigInteger xNumerator = p1.x.multiply(p2.y).add(p1.y).multiply(p2.x);
 		BigInteger xDenominator = BigInteger.ONE.add(d.multiply(p1.x)
 				                            .multiply(p2.x).multiply(p1.y).multiply(p2.y));
 		BigInteger yNumerator = p1.y.multiply(p2.y).subtract(p1.x).multiply(p2.x);
 		BigInteger yDenominator = BigInteger.ONE.subtract(d.multiply(p1.x)
                                          .multiply(p2.x).multiply(p1.y).multiply(p2.y));
 		
 		BigInteger x = xNumerator.multiply(xDenominator.modInverse(p)).mod(p);
 		BigInteger y = yNumerator.multiply(yDenominator.modInverse(p)).mod(p);
 		
 		return new ECPoint(x, y);
 	}
 	
 	public static  ECPoint sum(ECPoint p1, ECPoint p2) {
 		return new ECPoint(p1.x.add(p2.x).negate(), p1.y.add(p2.y));
 	}
 	
 	/**
 	 * Get the opposite of point (x, y)
 	 * 
 	 * @param p is a point on elliptic curve.
 	 * @return point (-x, y)
 	 */
 	public static ECPoint oppositePoint(ECPoint p) {
 		return new ECPoint(p.x.negate(), p.y);
 	}
 	
 	/**
 	 * Compare points for equality.
 	 * 
 	 * @param p1 is the 1st point on elliptic curve.
 	 * @param p2 is the 2nd point on elliptic curve.
 	 * @return either 0 (equal) or 1.
 	 */
 	public static int compare(ECPoint p1, ECPoint p2) {
 		return (p1.x.equals(p2.x) && p1.y.equals(p2.y)) ? 0 : 1;
 	}
	
	/**
	* Compute a square root of v mod p with a specified
	* least significant bit, if such a root exists.
	*
	* @param v the radicand.
	* @param p the modulus (must satisfy p mod 4 = 3).
	* @param lsb desired least significant bit (true: 1, false: 0).
	* @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
	* if such a root exists, otherwise null.
	*/
	public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
		assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
		if (v.signum() == 0) {
			return BigInteger.ZERO;
		}
		BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
		if (r.testBit(0) != lsb) {
			r = p.subtract(r); // correct the lsb
		}
		return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
	}

}
