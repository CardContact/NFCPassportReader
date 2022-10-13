//
//  PACEMapping.swift
//  
//
//  Created by Leif Erik Wagner on 12.10.22.
//

import Foundation
import OpenSSL

public class PACEMapping {
    
    /// Pseudo-random Number Mapping as defined by
    /// ICAO Doc 9303 Machine Readable Travel Documents, 2021
    /// Part 11: Security Mechanisms for MRTDs
    ///
    /// - Parameter s - byte array containing the nonce from the PICC
    /// - Parameter t - byte array containing the nonce from the PCD
    /// - Parameter p - Pointer to a BIGNUM containing the prime number (GFp)
    /// - Parameter algorithm - the cipher algorithm either AES or DESede
    /// - Returns the mapped EC_POINT on the curve
    public static func pseudoRandomFunction(s : [UInt8], t : [UInt8], p : OpaquePointer, algorithm : String) throws -> OpaquePointer {
        var result : [UInt8] = []
                
        // compute k0
        let iv : [UInt8]
        var key : [UInt8]
        if algorithm == "AES" {
            iv = [UInt8](repeating:0, count: 16)
            key = AESEncrypt(key: t, message: s, iv: iv)
        } else if algorithm == "DESede" {
            iv = [UInt8](repeating:0, count: 8)
            key = tripleDESEncrypt(key: t, message: s, iv: iv)
        } else {
            throw NFCPassportReaderError.PACEError("Step2IM", "Unable to convert rnd to bignum")
        }

        let l = s.count * 8

        // Key for deriving k_i
        let c0 : [UInt8]
        // Key fo deriving x_i
        let c1 : [UInt8]
        
        switch (l) {
        case 128:
            c0 = [0xa6, 0x68, 0x89, 0x2a, 0x7c, 0x41, 0xe3, 0xca, 0x73, 0x9f, 0x40, 0xb0, 0x57, 0xd8, 0x59, 0x04]
            c1 = [0xA4, 0xE1, 0x36, 0xAC, 0x72, 0x5F, 0x73, 0x8B, 0x01, 0xC1, 0xF6, 0x02, 0x17, 0xC1, 0x88, 0xAD]
            break
        case 192, 256:
            c0 = [0xd4, 0x63, 0xd6, 0x52, 0x34, 0x12, 0x4e, 0xf7, 0x89, 0x70, 0x54, 0x98, 0x6d, 0xca, 0x0a, 0x17, 0x4e, 0x28, 0xdf, 0x75, 0x8c, 0xba, 0xa0, 0x3f, 0x24, 0x06, 0x16, 0x41, 0x4d, 0x5a, 0x16, 0x76]
            c1 = [0x54, 0xbd, 0x72, 0x55, 0xf0, 0xaa, 0xf8, 0x31, 0xbe, 0xc3, 0x42, 0x3f, 0xcf, 0x39, 0xd6, 0x9b, 0x6c, 0xbf, 0x06, 0x66, 0x77, 0xd0, 0xfa, 0xae, 0x5a, 0xad, 0xd9, 0x9d, 0xf8, 0xe5, 0x35, 0x17]
        default:
            throw NFCPassportReaderError.PACEError("Step2IM", "Invalid size of nonce s")
        }

        let bits = BN_num_bits(p)
        
        var n = 0
        while (n * l < bits + 64) {
            let x : [UInt8]
            if algorithm == "AES" {
                x = AESEncrypt(key: key, message: c1, iv: iv)
                key = AESEncrypt(key: key, message: c0, iv: iv)
            } else {
                x = tripleDESEncrypt(key: key, message: c1, iv: iv)
                key = tripleDESEncrypt(key: key, message: c0, iv: iv)
            }
            result = result + x
            n = n + 1
        }
        
        let ctx = BN_CTX_new()
        let bn_result = BN_new()
        guard let bn_rnd = BN_bin2bn(result, Int32(result.count), nil) else {
            throw NFCPassportReaderError.PACEError("Step2IM", "Unable to convert rnd to bignum")
        }
        defer {
            BN_free(bn_rnd)
            BN_CTX_free(ctx)
        }
        
        // rnd mod p
        
        BN_div(nil, bn_result, bn_rnd, p, ctx)
        
        return bn_result!
    }
    
    /// TECHNICAL REPORT
    /// Supplemental Access Control for Machine Readable Travel Documents
    /// Version 1.01
    /// 5. Point Encoding for the Integrated Mapping
    ///
    /// - Parameter t - Pointer to a BIGNUM structure containing the field element to encode
    /// - Parameter curve - Pointer to an EC_GROUP containing the curve parameter
    /// - Returns the mapped EC_POINT on the curve
    public static func encodePointForIM(t : OpaquePointer, curve : OpaquePointer) -> OpaquePointer {
        let ctx = BN_CTX_new()
        let p = BN_new()
        let a = BN_new()
        let b = BN_new()
        let cofactor = BN_new()
        let alpha = BN_new()
        let alphaSq = BN_new()
        let alphaPlusAlphaSq = BN_new()
        let onePlusAlphaPlusAlphaSq = BN_new()
        let pMinus2 = BN_new()
        let x2 = BN_new()
        let tmpResult = BN_new()
        let x3 = BN_new()
        let h2 = BN_new()
        let bn_3 = BN_new()
        let u = BN_new()
        let bigA = BN_new()
        let pPlusOneOverFour = BN_new()
        let pMinusOneMinusPPlusOneOverFour = BN_new()
        let bn_4 = BN_new()
        let bigASqTimesH2 = BN_new()
        let y = BN_new()
        let result = EC_POINT_new(curve)

        defer {
            BN_free(alpha)
            BN_free(alphaSq)
            BN_free(alphaPlusAlphaSq)
            BN_free(onePlusAlphaPlusAlphaSq)
            BN_free(pMinus2)
            BN_free(x2)
            BN_free(tmpResult)
            BN_free(x3)
            BN_free(h2)
            BN_free(bn_3)
            BN_free(u)
            BN_free(bigA)
            BN_free(pPlusOneOverFour)
            BN_free(pMinusOneMinusPPlusOneOverFour)
            BN_free(bn_4)
            BN_free(bigASqTimesH2)
            BN_CTX_free(ctx)
        }
        
        EC_GROUP_get_curve(curve, p, a, b, ctx)
        
        // 1. Compute alpha = -t^2 mod p
        
        BN_mod_sqr(alpha, t, p, ctx)
        
        // Negate result
        BN_set_negative(alpha, 1)
        
        // mod p
        //BN_div(nil, alpha, alpha, p, ctx)
        BN_nnmod(alpha, alpha, p, ctx)
        
        // 2. Compute X_2 = -ba^-1 (1 + (alpha + alpha^2) ^-1) mod p
        // Rewrite as described in 5.2.2 to
        // -b (1 + alpha + alpha^2) (a (alpha + alpha^2)) ^p-2 mod p
        
        BN_mod_sqr(alphaSq, alpha, p, ctx)
        
        BN_mod_add(alphaPlusAlphaSq, alpha, alphaSq, p, ctx)
        
        BN_add(onePlusAlphaPlusAlphaSq, alphaPlusAlphaSq, BN_value_one())
        
        BN_sub(pMinus2, p, BN_value_one())
        BN_sub(pMinus2, pMinus2, BN_value_one())
        
        BN_set_negative(b, 1)
        
        BN_mul(x2, b, onePlusAlphaPlusAlphaSq, ctx)
        
        BN_mul(tmpResult, a, alphaPlusAlphaSq, ctx)
        BN_mod_exp(tmpResult, tmpResult, pMinus2, p, ctx)
        
        BN_mod_mul(x2, x2, tmpResult, p, ctx)
        
        // 3. Compute X_3 = alpha * X_2 mod p
        BN_mod_mul(x3, alpha, x2, p, ctx)
        
        // 4. Compute h_2 = (X_2)^3 + a*X_2 + b mod p
        BN_set_word(bn_3, 3)
        BN_mod_exp(h2, x2, bn_3, p, ctx)
        
        BN_mul(tmpResult, a, x2, ctx)
        BN_mod_add(h2, h2, tmpResult, p, ctx)
        
        BN_set_negative(b, 0)
        
        BN_mod_add(h2, h2, b, p, ctx)
        
        // Skip step 5.
        
        // 6. Compute U = t^3 * h_2 mod p
        BN_mod_exp(u, t, bn_3, p, ctx)
        BN_mod_mul(u, u, h2, p, ctx)
        
        // 7. Compute A = (h_2) ^p-1-(p+1)/4
        
        BN_add(pPlusOneOverFour, p, BN_value_one())
        BN_set_word(bn_4, 4)
        BN_mod_inverse(tmpResult, bn_4, p, ctx)
        BN_mod_mul(pPlusOneOverFour, pPlusOneOverFour, tmpResult, p, ctx)
        
        BN_sub(pMinusOneMinusPPlusOneOverFour, p, BN_value_one())
        BN_sub(pMinusOneMinusPPlusOneOverFour, pMinusOneMinusPPlusOneOverFour, pPlusOneOverFour)
        
        BN_mod_exp(bigA, h2, pMinusOneMinusPPlusOneOverFour, p, ctx)
        
        // 8. If A^2 * h_2 = 1 mod p define (x,y) = (X_2, A * h_2 mod p)
        
        BN_mod_sqr(bigASqTimesH2, bigA, p, ctx)
        BN_mod_mul(bigASqTimesH2, bigASqTimesH2, h2, p, ctx)
        
        if (BN_get_word(bigASqTimesH2) == 1) {
            BN_mod_mul(y, bigA, h2, p, ctx)
            EC_POINT_set_affine_coordinates(curve, result, x2, y, ctx)
        } else { // 9. Otherwise define (x,y) = (X_3, A * U mod p)
            BN_mod_mul(y, bigA, u, p, ctx)
            EC_POINT_set_affine_coordinates(curve, result, x3, y, ctx)
        }
        
        // 10. Output (x,y) = [f] (x,y)
        // Note: Step 10 requires a scalar multiplication by the co-factor f.
        // For many curves, the cofactor is equal to 1 so that this scalar
        // multiplication can be avoided.
        
        EC_GROUP_get_cofactor(curve, cofactor, ctx)
        
        if (BN_get_word(cofactor) == 1) {
            EC_POINT_make_affine(curve, result, ctx)
        } else {
            // point multiplication
            EC_POINT_mul(curve, result, nil, result, cofactor, ctx)
        }
        
        return result!
    }
    
    /// Does the Integrated Mapping with ECDH
    /// - Parameter t - Pointer to a BIGNUM structure containing the field element to encode
    /// - Parameter curve - Pointer to an EC_GROUP containing the curve parameter
    /// - Returns the EVP_PKEY containing the mapped ephemeral parameters
    public static func doECDHIntegratedMappingAgreement( t : OpaquePointer, curve: OpaquePointer ) throws -> OpaquePointer {
        
        let generator = self.encodePointForIM(t: t, curve: curve)
        
        let ephemeral_key = EC_KEY_new()
        defer{ EC_KEY_free(ephemeral_key) }
        
        EC_KEY_set_group(ephemeral_key, curve)
        
        guard let ephemeralParams = EVP_PKEY_new() else {
            throw NFCPassportReaderError.PACEError("Step2IM", "Unable to create ephemeral params")
        }
        
        let order = EC_GROUP_get0_order(curve)
        let cofactor = BN_new()
        let ctx = BN_CTX_new()
        defer {
            BN_free(cofactor)
            BN_CTX_free(ctx)
        }
        EC_GROUP_get_cofactor(curve, cofactor, ctx)
        
        guard EVP_PKEY_set1_EC_KEY(ephemeralParams, ephemeral_key) == 1,
              EC_GROUP_set_generator(curve, generator, order, cofactor) == 1,
              EC_GROUP_check(curve, nil) == 1,
              EC_KEY_set_group(ephemeral_key, curve) == 1 else {
            // Error

            EVP_PKEY_free( ephemeralParams )
            throw NFCPassportReaderError.PACEError("Step2IM", "Unable to configure new ephemeral params" )
        }
        
        return ephemeralParams
    }
}
