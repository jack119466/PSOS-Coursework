# ncrpt

This program is used to crypt and decrypt files.

## Binaries

Windows binary can be found in the releases section.

## Usage

Here is a video on YouTube: https://www.youtube.com/watch?v=-3_Q7j0UqKE

## Implementation

Basically, it takes a file and swaps 1st, 3rd and so on bits to their opposite (0 -> 1 and 1 -> 0).

## Compiling

`gcc -std=gnu11 ncrpt_*.c -o ncrpt_*.exe`

Don't forget to replace `*` with `mapping` or `direct`

You can use `-std=c99` instead. Also, you can add `-DNO_PROGRESS` (direct only) flag to turn off printing 
current progress. 
