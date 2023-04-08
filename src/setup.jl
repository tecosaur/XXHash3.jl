const STRIPE_LENGTH = 64
const SECRET_CONSUME_RATE = 8
const ACCUMULATOR_LANES = 8 # STRIPE_LENGTH ÷ sizeof(UInt64)

const PRIME32_1 = 0x9E3779B1            # 0b10011110001101110111100110110001
const PRIME32_2 = 0x85EBCA77            # 0b10000101111010111100101001110111
const PRIME32_3 = 0xC2B2AE3D            # 0b11000010101100101010111000111101

const PRIME64_1 = 0x9E3779B185EBCA87 # 0b1001111000110111011110011011000110000101111010111100101010000111
const PRIME64_2 = 0xC2B2AE3D27D4EB4F # 0b1100001010110010101011100011110100100111110101001110101101001111
const PRIME64_3 = 0x165667B19E3779F9 # 0b0001011001010110011001111011000110011110001101110111100111111001
const PRIME64_4 = 0x85EBCA77C2B2AE63 # 0b1000010111101011110010100111011111000010101100101010111001100011
const PRIME64_5 = 0x27D4EB2F165667C5 # 0b0010011111010100111010110010111100010110010101100110011111000101
const PRIME64_6 = 0x9FB21C651E98DF25 # 0b1001111110110010000111000110010100011110100110001101111100100101

const AVALANCHE_MAGIC_MIXER = 0x165667919E3779F9

mutable struct Accumulator
    data::NTuple{ACCUMULATOR_LANES, UInt64}
end

Accumulator() = Accumulator(
    (UInt64(PRIME32_3), PRIME64_1, PRIME64_2, PRIME64_3,
     PRIME64_4, UInt64(PRIME32_2), PRIME64_5, UInt64(PRIME32_1)))

Base.getindex(acc::Accumulator, i::Int) =
    GC.@preserve acc unsafe_load(Base.unsafe_convert(
        Ptr{UInt64}, pointer_from_objref(acc)), i)

Base.setindex!(acc::Accumulator, val::UInt64, i::Int) =
    GC.@preserve acc unsafe_store!(Base.unsafe_convert(
        Ptr{UInt64}, pointer_from_objref(acc)), val, i)

"""
    grab(T::Type{<:Unsigned}, bytes::Vector{UInt8}, index::Int=1, offset::Int=0)
Read a `T` from `bytes` at position `index`, in little endian form.

Compared to `reinterpret`, this allows for input arrays that aren't a multiple of
`sizeof(T)` in size, and avoids a bunch of overhead.
"""
function grab(T::Type{<:Unsigned}, bytes::Vector{UInt8}, index::Int=1)
    # @boundscheck checkbounds(bytes, index * sizeof(T))
    GC.@preserve bytes unsafe_load(Ptr{T}(pointer(bytes)), index) |> htol
end

function grab(T::Type{<:Unsigned}, bytes::Vector{UInt8}, index::Int, offset::Int)
    # @boundscheck checkbounds(bytes, index * sizeof(T) + offset)
    GC.@preserve bytes unsafe_load(Base.unsafe_convert(
        Ptr{UInt64}, pointer(bytes, 1 + sizeof(T) * (index - 1) + offset)), 1) |> htol
end

function grab(T::Type{<:Unsigned}, bytes::SubArray{UInt8, 1},
              index::Int=1, offset::Int=0)
    # @boundscheck checkbounds(bytes, index * sizeof(T) + offset)
    bindex = 1 + sizeof(T) * (index - 1) + bytes.offset1 + offset
    GC.@preserve bytes unsafe_load(Base.unsafe_convert(
        Ptr{UInt64}, pointer(bytes.parent, bindex)), 1) |> htol
end

const SECRET_MINSIZE = 136
const XXH_SECRET =
    [0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
     0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
     0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
     0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
     0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
     0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
     0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
     0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
     0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
     0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
     0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
     0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e]

rot32(val::UInt32, amount::Int) =
    val << (amount % 32) | (val  >> (32 - amount % 32))

function fold64(a::UInt64, b::UInt64)
    high, low = highlow(UInt128(a) * UInt128(b))
    xor(high, low)
end

xorshift(x::UInt64, shift::Int) = xor(x, x >> shift)

u128(high::UInt64, low::UInt64) = UInt128(high) << 64 + low
highlow(x::UInt128) = x >> 64 % UInt64, x % UInt64

avalanche(hash::UInt64) =
    xorshift(xorshift(hash, 37) * AVALANCHE_MAGIC_MIXER, 32)
