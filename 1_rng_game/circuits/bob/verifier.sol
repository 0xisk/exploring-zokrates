// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x1372ea930e10ed35a3faf7e1c8c5b0c22cf520c159d7de8d292cb8eec81747da), uint256(0x024fd34d84f5015c9056f3d6a4c648a27ea33504f75d47b5b996de17cf43a30f));
        vk.beta = Pairing.G2Point([uint256(0x2317e47917bd846d473e228ac78ad3bb7a7d706551a0b4f3c0791908e224eeeb), uint256(0x12e0eca71e5939258f21aba2b04a8f589c63c43b4864d681f0bde928f73948dd)], [uint256(0x0ec86d5a525c55ad430c6bf3462ac8da1901257ca5faac5be0a0bbdd799968bc), uint256(0x2ad3dee8f000bb278cc25f40c2ae784105b1de3aea4727de4a00aebf4e31f5ba)]);
        vk.gamma = Pairing.G2Point([uint256(0x18454dbd70bfc63146b98f75f94e2e2a8662d7572daebc9b2df3d36bc2e8c02e), uint256(0x24e6c12eb2e89e189db1ef840913b60e4899f187f6b3dd887048325a61aa05cf)], [uint256(0x27a3cd0e2cac740d8705e3451e304e174877f7c3df9ae6268352e1d244c8e64f), uint256(0x22daf62a7a6c431bd241879de102ffbe762e2b863d8888b6c216862628463358)]);
        vk.delta = Pairing.G2Point([uint256(0x3052a15d0903e5f2c6ffb44fe51ae7588d2f1e6203a1847f21a0be6ac31b36d1), uint256(0x11dfcbe99a4c88490fac2234e4fb88276a63388c09b6a6a482ae902eed6ed8ea)], [uint256(0x2b5b86bb95b3c6c17e43b31216de11b3eb0244842a6e4402b0731034a6bf20f3), uint256(0x17aa5fdffcc420e30a1fcc179262738f1e46dbdb5a7f8fe7cead8a838e247416)]);
        vk.gamma_abc = new Pairing.G1Point[](11);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x116bd423cd1fc0ecc64327f0dbd453afbe61f0c930c11a871f95646fd13432e8), uint256(0x0aedeea48545e0200fbbabc34eac01ef62ced626f13f49d4a2c9e30a5bb27abb));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x106d5b8acd217ae72e70e39c512eb927dc206162501309e557776878382612e3), uint256(0x03ad429a91def83d41e1d4708622c0d90f58fcf3138ed3be91e09aa5dd547d25));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0ed8a3740f6890c36e1afd56a81bb92cb978290691923acfe8d061a40e4ba213), uint256(0x100417ac4f0a9a524a86cafe6abf71f7a72e103a877118188b3a8ebacf4c8e02));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x184e2cca5642edb8668ec889853eb8878878cf2bd3c5bfa834348ba7661e4dae), uint256(0x0803ea092bf247c38616b09e8ef4b2735eb759c21221313e265917a6f22536c3));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1e89e73b518c1bbf105d8d10fb63c87be8d884b8bf103cdda54f66cf5c9a9b52), uint256(0x0f0dcee88459bf9443aacaede87bec168a4955c9c3ebd5037f4cebef7367d2f0));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x219f41f11cf3d0b19f7a4508fad91e1c3cdd97dcdc7cef3981c88a89a8e9be88), uint256(0x19233fd9fba5ea950493c7c550988c0a743fe3def7b4756e8f745d9711110b37));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0a9634ce3f8883921f2d4c9cd4350926fa91457cff3f93c76f361a390693e058), uint256(0x147f6879cc5318526edc433f51bb23d3c75f4045900a53923f2ac6ca048dc288));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x18e37542d52890daddfa9751054933dfc294ea8b5e6a28c279d03e04f6d5cc55), uint256(0x002cb6e3540e7fa1b7c3c91533ed22f28032099e0771d94f781ecb94e80c96c6));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x28b36a38d19494f0135027703d1ba3cf4565692b3c068bb9ad3ce197e92faf69), uint256(0x0aac2e321ba9bb3067ed1fc07cf060b99a3455aaae840d07080c9d7e3fcd9bb3));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x24e9f03737775da5038079096cd6b81683064e5894e46d120bbe892048106b97), uint256(0x26d04fd946d5f0b8f9830966fac619b28ec485869b536dc6e6fbbda835449cdd));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1af987c6a21038ada2c65a902563b7a92bd92a06e0e59ba0fdce27a5e2b6dd4a), uint256(0x29c12671a07b400d0bb86ea90d8db5a6f05ece1ae03b18a98b6c6553336b8365));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[10] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](10);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
