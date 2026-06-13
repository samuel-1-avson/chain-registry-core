// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 15956312590800383583402663177962482849181385120604221253138427401665694454712;
    uint256 constant alphay  = 15194225201476779988430949364614750402954679823541792670367967414449992322415;
    uint256 constant betax1  = 8347965492953092555456078172889248538976749974797172518702670848095292910207;
    uint256 constant betax2  = 978179707602655393618865274001269120399215626818916767136377048780252295587;
    uint256 constant betay1  = 6609615537200014268012357746920471015814830295580377222725105047333890932959;
    uint256 constant betay2  = 18860864254281811926055703696881005096608027597747701903836197785432648318951;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 15600249684646724981543573708044911464773928303889748587533364145155733148511;
    uint256 constant deltax2 = 18955162597227430295678942024176708413059695186657167840326927491221553496598;
    uint256 constant deltay1 = 3745219373138389183820594312588204306666256282508301014286374052628968896885;
    uint256 constant deltay2 = 14917167306425139232492910099166233024690263513847518249499748524523525797685;

    
    uint256 constant IC0x = 2859854972056536994355724146361917766437078588113617550415414900129880620197;
    uint256 constant IC0y = 12464687808541223607392556967302857609265531477878026051518554288451840870395;
    
    uint256 constant IC1x = 15551546501614440603590874726439304200170173828726142962604852842965870031217;
    uint256 constant IC1y = 11215883993912035567060030438352353649891886448870374796884854378565821957772;
    
    uint256 constant IC2x = 567841578708949582144216621109483506791738573710453994351433288042703930908;
    uint256 constant IC2y = 16485811253636220472755597834473631378071731792229864326159051733602842870010;
    
    uint256 constant IC3x = 516435474142469840009674385420202613242212044488674889099604585808168725825;
    uint256 constant IC3y = 16945202445247089807029752488835192792580914384008467351255961908548332324838;
    
    uint256 constant IC4x = 15827605994646058671933086498240982127927405459601957226161174464643833811242;
    uint256 constant IC4y = 17412303546484923693001728216956341519719152975739796148278591463283086194099;
    
    uint256 constant IC5x = 20259804688007006557432055986120119401389305350611435644357932141110636997294;
    uint256 constant IC5y = 4673034834870001456592041298659762638990781343126777842299144399068171982727;
    
    uint256 constant IC6x = 19306991685870855442496164999562967070125916800734961106487295302325833762451;
    uint256 constant IC6y = 6821492762518658835277787236177915489243003361521964400010030293206912162106;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[6] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                // sub(gas(), 2000): reserves 2 000 gas as a caller stipend before
                // forwarding to precompile 0x07 (ecMul).  The 2 000-gas reserve is
                // the historical idiom from EIP-1014; revisit if the ecMul precompile
                // cost is repriced in a future hard-fork (currently 6 000 gas, EIP-1108).
                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
