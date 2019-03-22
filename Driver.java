/**
 * Driver.java
 * 
 * TCSS 487 - Winter 2019
 * Programming Assignment 
 * 
 * Driver to run the app
 * 
 * @author Hien Doan
 * @version March 11, 2019
 */
import java.util.*;
import java.io.*;
import java.math.BigInteger;

public class Driver {
		
	/**
	 * Read the input file.
	 * 
	 * @param fileName is the name of input file.
	 * @return String contains the content of input file.
	 */
	private static String readFile(String fileName) {
		String text = "";
		try {
			Scanner inputFile = new Scanner(new File(fileName));
			while (inputFile.hasNext()) {
				text += inputFile.nextLine();
			}
			inputFile.close();
		} catch (Exception e) { // Catch error while opening file
			System.out.println("Cannot open the file! " + e);
			System.exit(1); 
		}
		return text;
	}
	
	/**
	 * Write result to the output file.
	 * 
	 * @param fileName is the name of output file.
	 * @param output is the content of output.
	 */
	private static void writeToFile(String fileName, String output) {
		PrintStream outputFile = null;

		try {
			outputFile = new PrintStream(new File(fileName));
		} catch (Exception e) {
			System.out.println("Difficulties opening the file! " + e);
			System.exit(1);
		}
		
		outputFile.println(output);
		outputFile.close();
	}
	
	/**
	 * Convert byte array to hex string adapted from 
	 * https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
	 * 
	 * @param a is the byte array to be converted.
	 * @return the hex string of byte array.
	 */
	public static String byteArrayToHex(byte[] a) {
		StringBuilder sb = new StringBuilder(a.length * 2);
		for(byte b: a) 
		   sb.append(String.format("%02x", b));
		return sb.toString();
	}
	
	/**
	 * Convert hex string to byte array adapted from 
	 * https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
	 * 
	 * @param s is the hex string to be converted. 
	 * @return the byte array.
	 */
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	/**
	 * Run Option 1: Compute a plain cryptographic hash.
	 */
	private static void runOption1() {
		System.out.println(); 
		boolean chosen = false;
		String plainText = "";
		while (!chosen) {
			System.out.println("Press 1 to use the given file,");
			System.out.println("      2 to enter a file,");
			System.out.println("      3 to enter a string,");
			System.out.println("      b to go back to main menu.");
			System.out.print("User input is: ");
			Scanner scan = new Scanner(System.in);
			String choice = scan.nextLine();
			
			if (choice.equals("1")) {
				plainText = readFile("test.txt");
				System.out.println(plainText);
				chosen = true;
				
			} else if (choice.equals("2")) {
				System.out.print("Enter the filename: ");
				String fileName = scan.nextLine();
				plainText = readFile(fileName);
				chosen = true;
				
			} else if (choice.equals("3")) {
				System.out.print("Enter a string: ");
				plainText = scan.nextLine();
				chosen = true;
				
			} else if (choice.equals("b") || choice.equals("B")) {
				startApp();
				chosen = true;
				
			} else {
				System.out.print("Please choose either 1, 2, 3 or b");
				startApp();
				chosen = false;
			}		
			scan.close();
		}
				
		// h <- KMACXOF256("", m, 512, "D")
		byte[] h = SHA3.KMACXOF256("".getBytes(), plainText.getBytes(), 512, "D".getBytes());
		
		// Print to screen as well as output file
		System.out.println("Cryptographic hash digest of the given text is: ");
		System.out.println(byteArrayToHex(h));
		System.out.println("Print cryptographic hash digest to output file HashDigest.txt");
		writeToFile("HashDigest.txt", byteArrayToHex(h));
	}
	
	/**
	 * Run Option 2: Encrypt/Decrypt symmetrically under a given passphrase.
	 */
	private static void runOption2() {
		System.out.println(); 
		boolean chosen = false;
	    
		while (!chosen) {
			System.out.println("Press 1 to encrypt/decrypt symmetrically under a given passphrase,");
			System.out.println("      2 to encrypt a file symmetrically under a given passphrase,");
			System.out.println("      3 to decrypt a symmetric cryptogram under a given passphrase,");
			System.out.println("      4 to compute an authentication tag,");
			System.out.println("      b to go back to main menu.");
			System.out.print("User input is: ");
			Scanner scan = new Scanner(System.in);
			String choice = scan.nextLine();
			
			if (choice.equals("1")) { // Encrypt & Decrypt
				chosen = true;
				System.out.print("Enter the filename: ");
				String fileName = scan.nextLine();
				String plainText = readFile(fileName);

				System.out.print("Enter the passphrase: ");
				String pw = scan.nextLine();		
				
				SymmetricCryptogram result  = new SymmetricCryptogram(); 
				result = SymmetricCryptogram.encrypt(plainText.getBytes(), pw.getBytes()); 			    
			    
			    System.out.println("Encrypting " + fileName + "...");
			    System.out.println("Symmetric cryptogram:");
			    System.out.println("  z = " + byteArrayToHex(result.getZ()));
			    System.out.println("  c = " + byteArrayToHex(result.getC()));
			    System.out.println("  t = " + byteArrayToHex(result.getT()));  
			    
			    System.out.println("Decrypting the symmetric cryptogram above...");
			    byte[] m = SymmetricCryptogram.decrypt(result, pw.getBytes());
				if (m == null) {
					System.out.println("Cannot decrypt!!!");
				} else {
					System.out.print("The original message is: ");
					try {
						String msg = new String(m, "UTF-8");
						System.out.println(msg);
					} catch (UnsupportedEncodingException e) {
							e.printStackTrace();
					}
				}
				
			} else if (choice.equals("2")) { // Encrypt only
				chosen = true;
				System.out.print("Enter the filename: ");
				String fileName = scan.nextLine();
				String plainText = readFile(fileName);

				System.out.print("Enter the passphrase: ");
				String pw = scan.nextLine();		
				
				SymmetricCryptogram result  = new SymmetricCryptogram(); 
				result = SymmetricCryptogram.encrypt(plainText.getBytes(), pw.getBytes()); 			    
			    
			    System.out.println("Encrypting " + fileName + "...");
			    System.out.println("Symmetric cryptogram:");
			    System.out.println("  z = " + byteArrayToHex(result.getZ()));
			    System.out.println("  c = " + byteArrayToHex(result.getC()));
			    System.out.println("  t = " + byteArrayToHex(result.getT()));  
			    
			    System.out.println("Symmetric cryptogram is printing to file SymEncrypt.txt");
			    writeToFile("SymEncrypt.txt", byteArrayToHex(result.getZ()) + "\n" 
			              + byteArrayToHex(result.getC()) + "\n" + byteArrayToHex(result.getT()));
				
			} else if (choice.equals("3")) { // Decrypt only
				chosen = true;
				String z = "", c = "", t = "";
				System.out.println("Press 1 to enter the symmetric cryptogram yourself or,");
				System.out.println("      2 to enter the filename contains the symmetric cryptogram.");
				System.out.print("User chooses: ");
				String option = scan.nextLine();
				
				if (option.equals("1")) {
					System.out.println("Enter the symmetric cryptogram");
					System.out.print("  z = ");
					z = scan.nextLine();
					System.out.print("  c = ");
					c = scan.nextLine();
					System.out.print("  t = ");
					t = scan.nextLine();
				} else if (option.equals("2")) {
					System.out.print("Enter the filename: ");
					String fileName = scan.next();
					String text = "";
					try {
						Scanner inputFile = new Scanner(new File(fileName));
						while (inputFile.hasNextLine()) {
							text += inputFile.nextLine() + "\n";
						}
						inputFile.close();
					} catch (Exception e) { // Catch error while opening file
						System.out.println("Cannot open the file! " + e);
						System.exit(1); 
					}
					String[] split = text.split("\n");
					z = split[0];
					c = split[1];
					t = split[2];
				}

				System.out.print("Enter the passphrase: ");
				String pw = scan.next();
			
				System.out.println("Decrypting the given symmetric cryptogram...");
				
				SymmetricCryptogram symCrypt = new SymmetricCryptogram(hexStringToByteArray(z),
						                                               hexStringToByteArray(c), 
						                                               hexStringToByteArray(t)); 
				byte[] m = SymmetricCryptogram.decrypt(symCrypt, pw.getBytes());
				if (m == null) {
					System.out.println("Cannot decrypt!!!");
				} else {
					System.out.print("The original message is: ");
					try {
						String msg = new String(m, "UTF-8");
						System.out.println(msg);
					} catch (UnsupportedEncodingException e) {
							e.printStackTrace();
					}
				}
				
			} else if (choice.equals("4")) { // authentication tag
				chosen = true;
				System.out.print("Enter the filename: ");
				String fileName = scan.nextLine();
				String plainText = readFile(fileName);

				System.out.print("Enter the passphrase: ");
				String pw = scan.nextLine();		
								
				// t <- KMACXOF256(pw, m, 512, "T")
				byte[] t = SHA3.KMACXOF256(pw.getBytes(), plainText.getBytes(), 512, "T".getBytes());
				
				// Print to screen as well as output file    		    
			    System.out.println("The authentication tag t of " + fileName + "is:");
			    System.out.println(byteArrayToHex(t));
			    System.out.println("The authentication tag t of " + fileName + " to output file AuthCode.txt");
				writeToFile("AuthCode.txt", byteArrayToHex(t));
				
			} else if (choice.equals("b")  || choice.equals("B")) {
				startApp();
				chosen = true;
				
			} else {
				System.out.print("Please choose either 1, 2, 3, 4 or b");
				startApp();
				chosen = false;
			}
			scan.close();
		}
	}
	
	/**
	 * Run Option 3: Generate an elliptic key pair from a given passphrase 
	 *               and write the public key to a file.
	 */
	private static void runOption3() {
		System.out.println(); 
		Scanner scan = new Scanner(System.in);
		System.out.print("Enter the filename to print the key pair: ");
		String fileName = scan.nextLine();
		System.out.print("Enter the passphrase: ");
		String pw = scan.nextLine();
		scan.close();
		
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
    	V = ECPoint.add(V, V);
    	
    	for (int i = 0; i < array.length; i++) {
    		V = ECPoint.add(V, V);
    		if (array[i] == '1') {
    			V = ECPoint.add(V, ECPoint.G);
    		}
    	}	
		
		System.out.println("The elliptic key pair (s, V) from the passphrase " + pw + " is: ");
		System.out.println("s = " + byteArrayToHex(s));
		System.out.println("V = (" + byteArrayToHex(V.getX().toByteArray()) + ", " + byteArrayToHex(V.getY().toByteArray()) + ")");

		System.out.println("Print the elliptic key pair (s, V) to file " + fileName);
		writeToFile(fileName, byteArrayToHex(s) 
						    + "\n" + byteArrayToHex(V.getX().toByteArray()) 
						    + "\n" + byteArrayToHex(V.getY().toByteArray())); 
	}
	
	/**
	 * Run Option 4: Encrypt/Decrypt elliptically.
	 */
	private static void runOption4() {
		System.out.println(); 
		boolean chosen = false;
	    
		while (!chosen) {
			System.out.println("Press 1 to encrypt a data file under a given elliptic public key file,");
			System.out.println("      2 to decrypt a given elliptic-encrypted file from a given password,");
			System.out.println("      3 to encrypt/decrypt text input directly from user input,");
			System.out.println("      b to go back to main menu.");
			System.out.print("User input is: ");
			Scanner scan = new Scanner(System.in);
			String choice = scan.nextLine();
			
			if (choice.equals("1")) { // Encrypt 
				chosen = true;
				System.out.print("Enter the filename: ");
				String fileName = scan.nextLine();
				String plainText = readFile(fileName);

				System.out.print("Enter the passphrase: ");
				String pw = scan.nextLine();		
				
				ECPoint V = Cryptogram.generatePublicKey(pw);
				Cryptogram result  = new Cryptogram(); 
				result = Cryptogram.encrypt(plainText.getBytes(), V); 			
				
				System.out.println("Encrypting " + fileName + "...");
			    System.out.println("Cryptogram:");
			    System.out.println("  Zx = " + result.getZ().getX());
			    System.out.println("  Zy = " + result.getZ().getY());
			    System.out.println("  c = " + byteArrayToHex(result.getC()));
			    System.out.println("  t = " + byteArrayToHex(result.getT()));  
			    
			    System.out.println("Asymmetric cryptogram is printing to file AsymEncrypt.txt");
			    writeToFile("AsymEncrypt.txt", result.getZ().getX() + "\n" + result.getZ().getY() + "\n"
			              + byteArrayToHex(result.getC()) + "\n" + byteArrayToHex(result.getT()));
				
				
			} else if (choice.equals("2")) { // Decrypt only
				chosen = true;
				
				String Zx = "", Zy = "", c = "", t = "";
				System.out.println("Press 1 to enter the symmetric cryptogram yourself or,");
				System.out.println("      2 to enter the filename contains the symmetric cryptogram.");
				System.out.print("User chooses: ");
				String option = scan.nextLine();
				
				if (option.equals("1")) {
					System.out.println("Enter the symmetric cryptogram");
					System.out.print("  Zx = ");
					Zx = scan.nextLine();
					System.out.print("  Zy = ");
					Zy = scan.nextLine();
					System.out.print("  c = ");
					c = scan.nextLine();
					System.out.print("  t = ");
					t = scan.nextLine();
				} else if (option.equals("2")) {
					System.out.print("Enter the filename: ");
					String fileName = scan.next();
					String text = "";
					try {
						Scanner inputFile = new Scanner(new File(fileName));
						while (inputFile.hasNextLine()) {
							text += inputFile.nextLine() + "\n";
						}
						inputFile.close();
					} catch (Exception e) { // Catch error while opening file
						System.out.println("Cannot open the file! " + e);
						System.exit(1); 
					}
					String[] split = text.split("\n");
					Zx = split[0];
					Zy = split[1];
					c = split[2];
					t = split[3];
				}
				
				
				System.out.print("Enter the passphrase: ");
				String pw = scan.next();
				
				ECPoint Z = new ECPoint(new BigInteger(Zx), new BigInteger(Zy));
				
				System.out.println("Decrypting the cryptogram above...");
			    byte[] m = Cryptogram.decrypt(new Cryptogram(Z, hexStringToByteArray(c), 
			    								hexStringToByteArray(t)),pw.getBytes());
				if (m == null) {
					System.out.println("Cannot decrypt!!!");
				} else {
					System.out.print("The original message is: ");
					try {
						String msg = new String(m, "UTF-8");
						System.out.println(msg);
					} catch (UnsupportedEncodingException e) {
							e.printStackTrace();
					}
				}			
				
			} else if (choice.equals("3")) { // Encrypt/Decrypt from user input
				chosen = true;
				System.out.print("Enter the string: ");
				String plainText = scan.nextLine();

				System.out.print("Enter the passphrase: ");
				String pw = scan.nextLine();		
				
				ECPoint V = Cryptogram.generatePublicKey(pw);
				Cryptogram result  = new Cryptogram(); 
				result = Cryptogram.encrypt(plainText.getBytes(), V); 	
				
				System.out.println("Encrypting " + plainText + "...");
			    System.out.println("Cryptogram:");
			    System.out.println("  Zx = " + result.getZ().getX());
			    System.out.println("  Zy = " + result.getZ().getY());
			    System.out.println("  c = " + byteArrayToHex(result.getC()));
			    System.out.println("  t = " + byteArrayToHex(result.getT()));  
				
			    System.out.println("Decrypting the cryptogram above...");
			    byte[] m = Cryptogram.decrypt(result, pw.getBytes());
				if (m == null) {
					System.out.println("Cannot decrypt!!!");
				} else {
					System.out.print("The original message is: ");
					try {
						String msg = new String(m, "UTF-8");
						System.out.println(msg);
					} catch (UnsupportedEncodingException e) {
							e.printStackTrace();
					}
				}
				
			} else if (choice.equals("b")  || choice.equals("B")) {
				startApp();
				chosen = true;
				
			} else {
				System.out.print("Please choose either 1, 2, 3 or b");
				startApp();
				chosen = false;
			}
			scan.close();
		}
	}
	
	/**
	 * Run Option 5: Sign the file and verify the signature.
	 */
	private static void runOption5() {
		System.out.println(); 
		boolean chosen = false;
		while (!chosen) {
			System.out.println("Press 1 to sign a file from a given password and write the signature to a file,");
			System.out.println("      2 to verify a file and its signature file under a given public key file,");
			System.out.println("      b to go back to main menu.");
			System.out.print("User input is: ");
			Scanner scan = new Scanner(System.in);
			String choice = scan.nextLine();
			
			if (choice.equals("1")) { 
				chosen = true;
				System.out.print("Enter the filename: ");
				String fileName = scan.nextLine();
				String plainText = readFile(fileName);

				System.out.print("Enter the passphrase: ");
				String pw = scan.nextLine();		
				
				Signature result = Signature.createSignature(plainText.getBytes(), pw.getBytes());
			    System.out.println("Signature:");
			    System.out.println("  h = " + byteArrayToHex(result.getH()));
			    System.out.println("  z = " + byteArrayToHex(result.getZ()));
			    
			    System.out.println("Write signature to the file Signature.txt" );
			    writeToFile("Signature.txt", byteArrayToHex(result.getH()) + "\n" + byteArrayToHex(result.getZ()));

				
			} else if (choice.equals("2")) { 
				chosen = true;
				System.out.print("Enter the filename contains the signature: ");
				String sigFile = scan.nextLine();
				String sigText = "";
				try {
					Scanner inputFile = new Scanner(new File(sigFile));
					while (inputFile.hasNextLine()) {
						sigText += inputFile.nextLine() + "\n";
					}
					inputFile.close();
				} catch (Exception e) { // Catch error while opening file
					System.out.println("Cannot open the file! " + e);
					System.exit(1); 
				}
				String[] split = sigText.split("\n");
				String h = split[0];
				String z = split[1];
				
				
				System.out.print("Enter the filename to verify the signature: ");
				String textFile = scan.nextLine();
				String text = readFile(textFile);
				System.out.print("Enter the passphrase to verify the signature: ");
				String pw = scan.nextLine();
				
				boolean result = Signature.verifySignature(new Signature(hexStringToByteArray(h), hexStringToByteArray(z)), 
						                             text.getBytes(), Cryptogram.generatePublicKey(pw));
				if (result) {
					System.out.println("The signature is verified!");
				} else {
					System.out.println("The signature does not match");
				}
				
			} else if (choice.equals("b")  || choice.equals("B")) {
				startApp();
				chosen = true;
				
			} else {
				System.out.print("Please choose either 1, 2 or b");
				startApp();
				chosen = false;
			}
			scan.close();
		}
		
	}
	
	/**
	 * Main menu of the app
	 */
	private static void startApp() {
		System.out.println("Welcome to the cryptography app!");
		
		boolean chosen = false;
		while (!chosen) {
			System.out.println("Press 1 to compute a plain cryptographic hash,");
			System.out.println("      2 to encrypt symmetric cryptogram under given passphrase,");
			System.out.println("      3 to generate an elliptic key pair and write public key to file,");
			System.out.println("      4 to encrypt/decrypt under elliptic public key,");
			System.out.println("      5 to sign a given file from given password and verify,");
			System.out.println("      q to quit the app.");
			System.out.print("User input is: ");
			Scanner scan = new Scanner(System.in);
			String choice = scan.nextLine();
			
			if (choice.equals("1")) {
				runOption1();
				chosen = true;
				
			} else if (choice.equals("2")) {
				runOption2();
				chosen = true;
				
			} else if (choice.equals("3")) {
				runOption3();
				chosen = true;
				
			} else if (choice.equals("4")) {
				runOption4();
				chosen = true;
				
			} else if (choice.equals("5")) {
				runOption5();
				chosen = true;
				
			} else if (choice.equals("q") || choice.equals("Q")) {
				System.out.print("Quitting the app...");
				System.exit(0); // Quit the app
				
			} else {
				System.out.println("Please choose options from 1 to 5, or q to quit\n");
				startApp();
				chosen = false;
			}		
			scan.close();
		}
	}
	
	/**
	 * Run the application
	 */
	public static void main(String[] args) {
		startApp();
	}

}
