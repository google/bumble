This dir contains samples firmware images in the format used for Realtek chips,
but with repetitions of the length of the section as a little-endian 32-bit int
for the patch data instead of actual firmware, since we only need the structure
to test parsing.