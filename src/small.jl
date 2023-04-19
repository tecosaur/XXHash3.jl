function hash0_128b(secret::AbstractVector{UInt8}, seed::UInt64)
    low = xor(PRIME64_1 + seed,
              grab(UInt64, secret, 9),
              grab(UInt64, secret, 10))
    high = xor(PRIME64_2 - seed,
               grab(UInt64, secret, 11),
               grab(UInt64, secret, 12))
    u128(avalanche(high), avalanche(low))
end

function hash1to3_128b(input::AbstractVector{UInt8}, secret::AbstractVector{UInt8}, seed::UInt64)
    byte1 = input[1] |> UInt32
    byte2 = input[1 + length(input) >> 1] |> UInt32
    byte3 = input[length(input)] |> UInt32
    combined_low = (byte1 << 16) | (byte2 << 24) | (byte3 << 0) |
        ((length(input) % UInt32) << 8)
    combined_high = rot32(bswap(combined_low), 13)
    bitflip_low = UInt64(grab(UInt32, secret, 1) ⊻ grab(UInt32, secret, 2)) + seed
    bitflip_high = UInt64(grab(UInt32, secret, 3) ⊻ grab(UInt32, secret, 4)) - seed
    low = UInt64(combined_low) ⊻ bitflip_low
    high = UInt64(combined_high) ⊻ bitflip_high
    u128(avalanche(high), avalanche(low))
end

function hash4to8_128b(input::AbstractVector{UInt8}, secret::AbstractVector{UInt8}, seed::UInt64)
    seed ⊻= UInt64(bswap(seed % UInt32)) << 32
    input_low = grab(UInt32, input)
    input_high = grab(UInt32, input, 1, length(input) - sizeof(UInt32))
    input_mixed = input_low + UInt64(input_high) << 32
    bitflip = grab(UInt64, secret, 3) ⊻ grab(UInt64, secret, 4)
    keyed = input_mixed ⊻ bitflip
    mixed = UInt128(keyed) * UInt128(PRIME64_1 + length(input) << 2)
    high, low = highlow(mixed)
    high += low << 1
    low ⊻= high >> 3
    low = xorshift(low, 35)
    low *= PRIME64_6
    low = xorshift(low, 28)
    u128(avalanche(high), low)
end

function hash9to16_128b(input::AbstractVector{UInt8}, secret::AbstractVector{UInt8}, seed::UInt64)
    bitflip_low = grab(UInt64, secret, 5) ⊻ grab(UInt64, secret, 6)
    bitflip_high = grab(UInt64, secret, 7) ⊻ grab(UInt64, secret, 8)
    input_low = grab(UInt64, input)
    input_high = grab(UInt64, input, 1, length(input) - sizeof(UInt64))
    mixed = UInt128(input_low ⊻ input_high ⊻ bitflip_low) * UInt128(PRIME64_1)
    high, low = highlow(mixed)
    low += (length(input) - 1) << 54
    input_high ⊻= bitflip_high
    high += input_high + UInt64(input_high % UInt32) * (PRIME64_2 - 1)
    low ⊻= bswap(high)
    high2, low2 = highlow(UInt128(low) * PRIME64_2)
    high2 += high * PRIME64_2
    u128(avalanche(high2), avalanche(low2))
end

function hash0to16_128b(input::AbstractVector{UInt8}, secret::AbstractVector{UInt8}, seed::UInt64)
    if length(input) >= 9
        hash9to16_128b(input, secret, seed)
    elseif length(input) >= 4
        hash4to8_128b(input, secret, seed)
    elseif length(input) > 0
        hash1to3_128b(input, secret, seed)
    else
        hash0_128b(secret, seed)
    end
end

function hash17to128_128b(input::AbstractVector{UInt8}, secret::AbstractVector{UInt8}, seed::UInt64)
    high = zero(UInt64)
    low = length(input) * PRIME64_1
    if length(input) > 96
        high, low = mix32b((high, low),
                           (@view input[6*8+1:end]), (@view input[end-8*8+1:end]),
                           (@view secret[12*8+1:end]), seed)
    elseif length(input) > 64
        high, low = mix32b((high, low),
                           (@view input[4*8+1:end]), (@view input[end-6*8+1:end]),
                           (@view secret[8*8+1:end]), seed)
    elseif length(input) > 32
        high, low = mix32b((high, low),
                           (@view input[2*8+1:end]), (@view input[end-4*8+1:end]),
                           (@view secret[4*8+1:end]), seed)
    else
        high, low = mix32b((high, low),
                           (@view input[0*8+1:end]), (@view input[end-2*8+1:end]),
                           (@view secret[0*8+1:end]), seed)
    end
    low2 = low + high
    high2 = low * PRIME64_1 + high * PRIME64_4 + (length(input) - seed) * PRIME64_2
    u128(zero(UInt64) - avalanche(high2), avalanche(low2))
end

function hash129to240_128b(input::AbstractVector{UInt8}, secret::AbstractVector{UInt8}, seed::UInt64)
    midsize_start_offset = 3
    midsize_last_offset = 17
    high = zero(UInt64)
    low = length(input) * PRIME64_1
    for i in 32:32:128
        high, low = mix32b((high, low),
                           (@view input[i-31:end]),
                           (@view input[i-15:end]),
                           (@view secret[i-31:end]),
                           seed)
    end
    high, low = avalanche(high), avalanche(low)
    for i in 160:32:length(input)
        high, low = mix32b((high, low),
                           (@view input[i-31:end]),
                           (@view input[i-15:end]),
                           (@view secret[midsize_start_offset + i-159:end]),
                           seed)
    end
    high, low = mix32b((high, low),
                       (@view input[end-15:end]),
                       (@view input[end-31:end]),
                       (@view secret[SECRET_MINSIZE - midsize_last_offset - 15:end]),
                       zero(UInt64) - seed)
    low2 = low + high
    high2 = low * PRIME64_1 + high * PRIME64_4 + (length(input) - seed) * PRIME64_2
    u128(zero(UInt64) - avalanche(high2), avalanche(low2))
end
