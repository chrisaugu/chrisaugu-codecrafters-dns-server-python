# shift operator

## right shift
2   = 00000010
5   = 00000101
20  = 00010100
40  = 00101000

5 << 2 = 20
20  = 00010100

5 << 3 = 40
40  = 00101000

5 <<< 2 = 
0   = 00000000

5 <<< 3 =

## left shift
0   = 00000000
1   = 00000001
2   = 00000010
5   = 00000101

5 >> 2 = 1
1   = 00000001

5 >> 3 = 0
0   = 00000000

5 >>> 2 = 1
1   = 00000001

5 >>> 3 = 0
0   = 00000000


# bitwise AND (&) operator
2   = 00000010
3   = 00000011
4   = 00000100
5   = 00000101
20  = 00010100
40  = 00101000

3 & 5 = 1
1   = 00000001

2 & 5 = 0
0   = 00000000

4 & 5 = 4
4   = 00000100


# bitwise NOT (~) operator
The bitwise NOT (~) operator returns a number or BigInt whose binary representation has a 1 in each bit position for which the corresponding bit of the operand is 0, and a 0 otherwise.

2   = 00000010
3   = 00000011
4   = 00000100
5   = 00000101
7   = 00001111

5 | 3 = 7
7   = 00001111



# bitwise OR (|) operator
The bitwise OR (|) operator returns a number or BigInt whose binary representation has a 1 in each bit position for which the corresponding bits of either or both operands are 1.

2   = 00000010
3   = 00000011
4   = 00000100
5   = 00000101
7   = 00001111

5 | 3 = 7
7   = 00001111



# bitwise XOR (^) operator
