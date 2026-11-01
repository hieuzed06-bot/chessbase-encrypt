import test from 'node:test';
import assert from 'node:assert/strict';
import { byteToMove, moveToByte, toPGN, fromPGN } from '../codec.js';
test('all 256 byte values round-trip',()=>{for(let i=0;i<256;i++)assert.equal(moveToByte(byteToMove(i)),i);});
test('PGN round-trip preserves bytes',()=>{const input=Uint8Array.from({length:256},(_,i)=>i);assert.deepEqual(fromPGN(toPGN(input)),input);});
test('accepts move numbers and result markers',()=>{assert.deepEqual(fromPGN('[Event "Secret"]\n\n1. a1 Nb3 2... Rc4 *'),Uint8Array.of(0,74,211));});
test('rejects malformed tokens, SAN, comments and empty PGN',()=>{for(const p of ['', '1. exd5 O-O *','1. a1 {comment} *','1. a9 *','[Event broken]\n\n1. a1'])assert.throws(()=>fromPGN(p));});
test('rejects oversized PGN',()=>{assert.throws(()=>fromPGN('a'.repeat(2*1024*1024+1)),/2 MiB/);});
