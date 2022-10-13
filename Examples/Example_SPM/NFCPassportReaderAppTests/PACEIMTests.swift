//
//  PACEIMTests.swift
//
//  Created by Leif Erik Wagner on 11.10.22.
//

import XCTest
import NFCPassportReader
import OpenSSL

final class PACEIMTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testPseudoRandomFunction() throws {
        let s = hexRepToBin("2923BE84E16CD6AE529049F1F1BBE9EB");
        let t = hexRepToBin("5DD4CBFC96F5453B130D890A1CDBAE32");
        let p = hexRepToBin("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377")
        let bn_p = BN_bin2bn(p, Int32(p.count), nil)
        defer { BN_free(bn_p) }
        
        let bn_result = try PACEMapping.pseudoRandomFunction(s: s, t: t, p: bn_p!, algorithm: "AES")
        
        var result : [UInt8] = []
        let count = (BN_num_bits(bn_result)+7)/8
        result = [UInt8](repeating: 0, count: Int(count))
        BN_bn2bin(bn_result, &result)
        
        let ref : [UInt8] = hexRepToBin("A2F8FF2DF50E52C6599F386ADCB595D229F6A167ADE2BE5F2C3296ADD5B7430E")
        XCTAssertEqual(result, ref)
    }

    func testEncodePointForIM() throws {
        let rnd : [UInt8] = hexRepToBin("A2F8FF2DF50E52C6599F386ADCB595D229F6A167ADE2BE5F2C3296ADD5B7430E")
        let bn_rnd = BN_bin2bn(rnd, Int32(rnd.count), nil)
        
        let curve = EC_GROUP_new_by_curve_name(NID_brainpoolP256r1)
        
        let result = PACEMapping.encodePointForIM(t: bn_rnd!, curve: curve!)
        
        let bn_x = BN_new()
        let bn_y = BN_new()
        defer { BN_free(bn_x); BN_free(bn_y) }
        EC_POINT_get_affine_coordinates(curve, result, bn_x, bn_y, nil)
        
        let countX = (BN_num_bits(bn_x)+7)/8
        var x = [UInt8](repeating: 0, count: Int(countX))
        BN_bn2bin(bn_x, &x)
        
        let countY = (BN_num_bits(bn_y)+7)/8
        var y = [UInt8](repeating: 0, count: Int(countY))
        BN_bn2bin(bn_y, &y)
        
        let refX : [UInt8] = hexRepToBin("8E82D31559ED0FDE92A4D0498ADD3C23BABA94FB77691E31E90AEA77FB17D427")
        let refY : [UInt8] = hexRepToBin("4C1AE14BD0C3DBAC0C871B7F3608169364437CA30AC243A089D3F266C1E60FAD")
        
        XCTAssertEqual(x, refX)
        XCTAssertEqual(y, refY)
    }

    func testDoECDHIntegratedMappingAgreement() throws {
        let rnd : [UInt8] = hexRepToBin("A2F8FF2DF50E52C6599F386ADCB595D229F6A167ADE2BE5F2C3296ADD5B7430E")
        let bn_rnd = BN_bin2bn(rnd, Int32(rnd.count), nil)
        
        let curve = EC_GROUP_new_by_curve_name(NID_brainpoolP256r1)
        
        let result = try PACEMapping.doECDHIntegratedMappingAgreement(t: bn_rnd!, curve: curve!)
        
        let test_key = EVP_PKEY_get1_EC_KEY(result)
        
        let test_group = EC_KEY_get0_group(test_key)
        let test_generator = EC_GROUP_get0_generator(test_group)
        
        let bn_x = BN_new()
        let bn_y = BN_new()
        defer { BN_free(bn_x); BN_free(bn_y) }
        EC_POINT_get_affine_coordinates(curve, test_generator, bn_x, bn_y, nil)
         
        let countX = (BN_num_bits(bn_x)+7)/8
        var x = [UInt8](repeating: 0, count: Int(countX))
        BN_bn2bin(bn_x, &x)
        
        let countY = (BN_num_bits(bn_y)+7)/8
        var y = [UInt8](repeating: 0, count: Int(countY))
        BN_bn2bin(bn_y, &y)
        
        let refX : [UInt8] = hexRepToBin("8E82D31559ED0FDE92A4D0498ADD3C23BABA94FB77691E31E90AEA77FB17D427")
        let refY : [UInt8] = hexRepToBin("4C1AE14BD0C3DBAC0C871B7F3608169364437CA30AC243A089D3F266C1E60FAD")
        
        XCTAssertEqual(x, refX)
        XCTAssertEqual(y, refY)
    }
}
