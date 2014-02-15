/**
 * CardApplet.java
 *
 * JavaCard operations
 *
 * Copyright (C) Pim Vullers, March 2010.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package applet;

import com.nxp.id.jcopx.KeyAgreementX;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

/**
 * JavaCard applet class
 */
public class CardApplet extends Applet {

    public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant applet registration
		new CardApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    private static final short _0 = 0;
    private static final short KEY_LENGTH = KeyBuilder.LENGTH_EC_FP_128;
    private static final short ATTRIBUTE_COUNT = 4;
    private static final short KEY_SIZE = KEY_LENGTH / 8;
    private static final short POINT_SIZE = KEY_SIZE * 2 + 1;
    private static final short ATTRIBUTE_SIZE = KEY_SIZE + POINT_SIZE + 4;

    private boolean initialised = false;

    private KeyAgreement agreement;

    private ECPrivateKey privKey;
    private ECPublicKey pubKey;
    private KeyPair keyPair;

    private ECPrivateKey blindKeyValue;
    private ECPublicKey blindKeyPoint;
    private KeyPair blindKeyPair;

    private byte[] attribute_id;
    private short[] attribute_length;
    private Object[] attribute_signature;
    private Object[] attribute_value;

    private byte[] public_key;

    private byte[] point;

    /**
     * Allocate memory for the data on the card and initialise the fields
     */
    public CardApplet() {
		// Get instances of cryptographic operations
		agreement = KeyAgreementX.getInstance(KeyAgreementX.ALG_EC_SVDP_DH_PLAIN, false);

		// Build keys
		privKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KEY_LENGTH, false);
		pubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KEY_LENGTH, false);
		blindKeyValue = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KEY_LENGTH, false);
		blindKeyPoint = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KEY_LENGTH, false);
		public_key = new byte[POINT_SIZE];

		// Construct key pairs
		keyPair = new KeyPair(pubKey, privKey);
		blindKeyPair = new KeyPair(blindKeyPoint, blindKeyValue);

		// Construct attribute storage
		attribute_id = new byte[ATTRIBUTE_COUNT];
		Util.arrayFillNonAtomic(attribute_id, _0, ATTRIBUTE_COUNT, (byte) 0x00);
		attribute_length = new short[ATTRIBUTE_COUNT];
		attribute_signature = new Object[ATTRIBUTE_COUNT];
		attribute_value = new Object[ATTRIBUTE_COUNT];
		for (short i = 0; i < ATTRIBUTE_COUNT; i++) {
		    attribute_signature[i] = new byte[POINT_SIZE];
		    attribute_value[i] = new byte[ATTRIBUTE_SIZE];
		}

		// Some temporary space
		point = JCSystem.makeTransientByteArray((short) (POINT_SIZE*2), JCSystem.CLEAR_ON_RESET);
    }

    /**
     * Process an incoming APDU command, i.e. select the appropriate method
     */
    public void process(APDU apdu) {
    	// Good practice: Return 9000 on SELECT
    	if (selectingApplet()) return;

    	// Select the appropriate method
    	apdu.setIncomingAndReceive();
    	byte[] buffer = apdu.getBuffer();
    	switch (buffer[ISO7816.OFFSET_INS]) {

    		case (byte) 0x01:
  				initialise(apdu);
  				break;

	    	case (byte) 0x02:
	    		personalise(apdu);
	    		break;

	    	case (byte) 0x03:
	    		getAttribute(apdu);
	    		break;

        case (byte) 0x04:
          getKey(apdu);
          break;

        default:
        	// Good practice: If you don't know the INStruction, say so:
         	ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    	}
    }

    /**
     * Initialise the cryptographic parameters on the card
     *
     * @param apdu APDU containing the prime number for the finite field F_P,
     * 		the order of the elliptic curve, A and B parameters defining
     * 		the curve: y^2 = x^3 + Ax + B (mod P) and a generator point on
     * 		the curve
     */
    private void initialise(APDU apdu) {
		short length, offset = ISO7816.OFFSET_CDATA;
		byte[] buffer = apdu.getBuffer();

		try {
		    if(initialised) {
		        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		    }
		    // Set the field prime P
		    length = Util.getShort(buffer, offset);
		    offset += 2;
		    privKey.setFieldFP(buffer, offset, length);
		    pubKey.setFieldFP(buffer, offset, length);
		    blindKeyValue.setFieldFP(buffer, offset, length);
		    blindKeyPoint.setFieldFP(buffer, offset, length);
		    offset += length;

		    // Set the curve order R
		    length = Util.getShort(buffer, offset);
		    offset += 2;
		    privKey.setR(buffer, offset, length);
		    pubKey.setR(buffer, offset, length);
		    blindKeyValue.setR(buffer, offset, length);
		    blindKeyPoint.setR(buffer, offset, length);
		    offset += length;

		    // Set the curve parameter A
		    length = Util.getShort(buffer, offset);
		    offset += 2;
		    privKey.setA(buffer, offset, length);
		    pubKey.setA(buffer, offset, length);
		    blindKeyValue.setA(buffer, offset, length);
		    blindKeyPoint.setA(buffer, offset, length);
		    offset += length;

		    // Set the curve parameter B
		    length = Util.getShort(buffer, offset);
		    offset += 2;
		    privKey.setB(buffer, offset, length);
		    pubKey.setB(buffer, offset, length);
		    blindKeyValue.setB(buffer, offset, length);
		    blindKeyPoint.setB(buffer, offset, length);
		    offset += length;

		    // Set the generator point G
		    length = Util.getShort(buffer, offset);
		    offset += 2;
		    privKey.setG(buffer, offset, length);
		    pubKey.setG(buffer, offset, length);
		    blindKeyValue.setG(buffer, offset, length);
		    blindKeyPoint.setG(buffer, offset, length);
		    offset += length;

		    // Switch APDU mode
		    apdu.setOutgoing();
		    apdu.setOutgoingLength((short) (length + 2));
		    offset = 0;

		    // Generate a key pair
		    boolean privIsNat = false;
		    while (!privIsNat) {
				keyPair.genKeyPair();
				((ECPrivateKey)keyPair.getPrivate()).getS(buffer, offset);
				privIsNat = (buffer[0] & 0x80) == 0x00;
		    }

		    // Store the public key in an array to avoid copying later on
		    pubKey.getW(public_key, _0);

		    // Return the cards public key
		    length = pubKey.getW(buffer, (short) (offset + 2));
		    Util.setShort(buffer, offset, length);
		    offset += length + 2;

		    // Send response
		    apdu.sendBytes(_0, offset);
            initialised = true;
		} catch (CryptoException e) {
		    ISOException.throwIt((short) ((short)0x5000 + offset | (e.getReason() << 8)));
		} catch (APDUException e) {
		    ISOException.throwIt((short) ((short)0x7000 + offset | (e.getReason() << 8)));
		} catch (Exception e) {
		    ISOException.throwIt((short) ((short)0x8000 + offset));
		}
    }


    /**
     * Initialise the cryptographic parameters on the card
     *
     * @param apdu APDU containing the prime number for the finite field F_P,
     *          the order of the elliptic curve, A and B parameters defining
     *          the curve: y^2 = x^3 + Ax + B (mod P) and a generator point on
     *          the curve
     */
    private void getKey(APDU apdu) {
        short length, offset = 0;

        try {
            // Switch APDU mode
            apdu.setOutgoing();
            byte[] buffer = apdu.getBuffer();
            length = pubKey.getW(buffer, (short) (offset + 2));
            apdu.setOutgoingLength((short) (length + 2));

            // Return the cards public key
            Util.setShort(buffer, offset, length);
            offset += length + 2;

            // Send response
            apdu.sendBytes(_0, offset);

        } catch (CryptoException e) {
            ISOException.throwIt((short) ((short)0x5000 + offset | (e.getReason() << 8)));
        } catch (APDUException e) {
            ISOException.throwIt((short) ((short)0x7000 + offset | (e.getReason() << 8)));
        }
    }

    /**
     * Store a number of attributes (with corresponding signatures) on the card
     *
     * @param apdu APDU containing attribute/signature pairs
     */
    private void personalise(APDU apdu) {
	short offset = ISO7816.OFFSET_CDATA;
	byte[] buffer = apdu.getBuffer();

	// Set attributeCount
	short attribute_count = Util.getShort(buffer, offset);
	offset += 2;

	for (short k = 0; k < attribute_count; k++) {
	    // Store the attribute ID (1 byte)
	    short index = (short)(buffer[offset]-1);
	    attribute_id[index] = buffer[offset];
	    offset += 1;

	    // Store the attribute signature (POINT_SIZE bytes)
	    Util.arrayCopyNonAtomic(buffer, offset, (byte[]) attribute_signature[index], _0, POINT_SIZE);
	    offset += POINT_SIZE;

	    // Store the length of the attribute (1 short == 2 bytes)
	    attribute_length[index] = Util.getShort(buffer, offset);
	    offset += 2;

	    // Store the attribute value and its length (length bytes)
	    Util.arrayCopyNonAtomic(buffer, offset, (byte[]) attribute_value[index], _0, attribute_length[index]);
	    offset += attribute_length[index];
	}
    }

    /**
     * Get an attribute from the card
     *
     * @param apdu APDU containing the index of the attribute
     * @return Blinded public key, blinded attribute signature and the attribute
     */
    private void getAttribute(APDU apdu) {
	short length = 0, index = 0, offset = ISO7816.OFFSET_CDATA;
	byte[] buffer = apdu.getBuffer();

	try {
            // Get the index, i.e. look-up the id, throw exception if not found
            byte id = buffer[offset++];
            while (index < ATTRIBUTE_COUNT && attribute_id[index] != id) {
        	index++;
            }
            if (index >= ATTRIBUTE_COUNT || attribute_id[index] != id) {
        	ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
            }

            // Get the nonce send by the terminal
            length = Util.getShort(buffer, offset);
	    offset += 2;
	    blindKeyPoint.setG(buffer, offset, length);
	    blindKeyValue.setG(buffer, offset, length);

	    // Switch APDU mode
	    apdu.setOutgoing();
	    apdu.setOutgoingLength((short) (KEY_SIZE * 3 + attribute_length[index] + 8));
	    offset = 0;

	    // Generate a blinding factor b, store it in blinder and blindKey
	    blindKeyPair.genKeyPair();

	    // Sign the nonce using the private key
	    agreement.init(privKey);
	    blindKeyPoint.getW(point, _0);
	    length = agreement.generateSecret(point, _0, POINT_SIZE, buffer, (short) (offset + 2));
	    Util.setShort(buffer, offset, length);
	    offset += length + 2;

	    // Blind the public key using the blinding factor
	    agreement.init(blindKeyValue);
	    length = agreement.generateSecret(public_key, _0, POINT_SIZE, buffer, (short) (offset + 2));
	    Util.setShort(buffer, offset, length);
	    offset += length + 2;

	    // Blind attribute signature, which is at attr_index + 2*lengthvalues.length + attribute_value.length
	    length = agreement.generateSecret((byte[]) attribute_signature[index], _0, POINT_SIZE, buffer, (short) (offset + 2));
	    Util.setShort(buffer, offset, length);
	    offset += length + 2;

	    // Append attribute
	    Util.arrayCopyNonAtomic((byte[]) attribute_value[index], _0, buffer, (short) (offset + 2), attribute_length[index]);
	    Util.setShort(buffer, offset, attribute_length[index]);
	    offset += attribute_length[index] + 2;

	    // Send response
	    apdu.sendBytes(_0, offset);

	} catch (CryptoException e) {
	    ISOException.throwIt((short) ((short)0x5000 + offset | (e.getReason() << 8)));
	} catch (APDUException e) {
	    ISOException.throwIt((short) ((short)0x7000 + offset | (e.getReason() << 8)));
	} catch (NullPointerException e) {
	    ISOException.throwIt((short) ((short)0x8000 + offset));
	} catch (ArrayIndexOutOfBoundsException e) {
	    ISOException.throwIt((short) ((short)0x8100 + offset));
	}
    }
}
