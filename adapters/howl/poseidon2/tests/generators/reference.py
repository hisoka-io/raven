"""Poseidon2-BN254 reference, transcribed from the Yul and checked against Barretenberg.

Structure read from darkpool-v2 .../Poseidon/LibPoseidon2Yul.sol, which cites
github.com/zemse/poseidon2-evm (MIT). Constants extracted from that file by usage frequency:
88 appear exactly once (round constants, in application order) and 4 appear 56 times each
(the internal diagonal, one use per partial round).
"""
import json, pathlib

P = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
C = json.load(open(pathlib.Path(__file__).parent / "yul-constants.json"))
RC = [int(h, 16) for h in C["round_constants_in_order"]]
DIAG = [int(h, 16) for h in C["repeated"]]
R_F, R_P, T = 8, 56, 4
assert len(RC) == R_F * T + R_P, len(RC)
assert len(DIAG) == T

def sbox(x): return pow(x, 5, P)

def m4(s):
    t0 = s[0] + s[1]
    t1 = s[2] + s[3]
    t2 = 2 * s[1] + t1
    t3 = 2 * s[3] + t0
    t4 = 4 * t1 + t3
    t5 = 4 * t0 + t2
    t6 = t3 + t5
    t7 = t2 + t4
    return [t6 % P, t5 % P, t7 % P, t4 % P]

def permutation(state):
    s = [x % P for x in state]
    s = m4(s)
    k = 0
    for _ in range(R_F // 2):                       # external, first half
        s = [(s[i] + RC[k + i]) % P for i in range(T)]
        k += T
        s = [sbox(x) for x in s]
        s = m4(s)
    for _ in range(R_P):                            # internal
        s[0] = (s[0] + RC[k]) % P
        k += 1
        s[0] = sbox(s[0])
        tot = sum(s) % P
        s = [(s[i] * DIAG[i] + tot) % P for i in range(T)]
    for _ in range(R_F // 2):                       # external, second half
        s = [(s[i] + RC[k + i]) % P for i in range(T)]
        k += T
        s = [sbox(x) for x in s]
        s = m4(s)
    assert k == len(RC), (k, len(RC))
    return s

TWO64 = 1 << 64

def hash_fields(inputs):
    """Sponge: rate 3, capacity index 3, iv = len * 2^64, squeeze returns state[0]."""
    s = [0, 0, 0, (len(inputs) * TWO64) % P]
    cache = []
    def duplex():
        nonlocal s, cache
        for i, c in enumerate(cache):
            s[i] = (s[i] + c) % P
        s = permutation(s)
        cache = []
    for x in inputs:
        if len(cache) == 3:
            duplex()
        cache.append(x % P)
    duplex()
    return s[0]
