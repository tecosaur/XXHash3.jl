function mix16b(input::AbstractVector{UInt8}, secret::AbstractVector{UInt8}, seed::UInt64)
    low = grab(UInt64, input, 1)
    high = grab(UInt64, input, 2)
    fold64(low ⊻ (grab(UInt64, secret, 1) + seed),
           high ⊻ (grab(UInt64, secret, 2) - seed))
end

function mix32b((high, low)::NTuple{2, UInt64},
                a::AbstractVector{UInt8}, b::AbstractVector{UInt8},
                secret::AbstractVector{UInt8}, seed::UInt64)
    low += mix16b(a, secret, seed)
    low ⊻= grab(UInt64, b, 1) + grab(UInt64, b, 2)
    high += mix16b(b, (@view secret[17:end]), seed)
    high ⊻= grab(UInt64, a, 1) + grab(UInt64, a, 2)
    high, low
end
const SECRET_ACCUMULATOR_START = 7

function hash_inner_loop(acc::Accumulator, input::AbstractVector{UInt8}, secret::AbstractVector{UInt8})
    stripes_per_block = (length(secret) - STRIPE_LENGTH) ÷ SECRET_CONSUME_RATE
    block_length = STRIPE_LENGTH * stripes_per_block
    num_blocks = (length(input) - 1) ÷ block_length

    for n in 1:num_blocks
        accumulate!(acc, (@view input[1+(n-1)*block_length:end]), secret, stripes_per_block)
    end
    # Last partial block
    num_stripes = (length(input) - 1 - block_length * num_blocks) ÷ STRIPE_LENGTH
    accumulate!(acc, (@view input[1 + block_length * num_blocks:end]),
                secret, num_stripes)
    # Last stripe
    accumulate!(acc, (@view input[end - STRIPE_LENGTH + 1:end]),
                secret[end - STRIPE_LENGTH - SECRET_ACCUMULATOR_START + 1:end])
    acc
end

const SECRET_MERGE_START_OFFSET = 11 # do not align on 8, so that the secret is different from the accumulator

function hash_128b_inner(input::AbstractVector{UInt8}, secret::AbstractVector{UInt8})
    acc = Accumulator()
    hash_inner_loop(acc, input, secret)
    high = mergestate(acc, (@view secret[end - sizeof(acc.data) - SECRET_MERGE_START_OFFSET:end]),
                      length(input) * PRIME64_1)
    low = mergestate(acc, (@view secret[1+SECRET_MERGE_START_OFFSET:end]),
                     ~(length(input) * PRIME64_2))
    u128(high, low)
end

function accumulate!(acc::Accumulator, input::AbstractVector{UInt8},
                     secret::AbstractVector{UInt8}, num_stripes::Int)
    for n in 1:num_stripes
        accumulate!(acc, (@view input[1 + (n-1) * STRIPE_LENGTH:end]),
                    (@view secret[1 + 8*(n-1):end]))
    end
    acc
end

function accumulate!(acc::Accumulator, input::AbstractVector{UInt8}, secret::AbstractVector{UInt8})
    for i in 1:ACCUMULATOR_LANES
        val = grab(UInt64, input, i)
        acc[(i-1) ⊻ 1] += val
        val ⊻= secret[i]
        acc[i] += (val % UInt32) * (val >> 32)
    end
    acc
end

function scramble!(acc::Accumulator, secret::AbstractVector{UInt8})
    for i in 1:ACCUMULATOR_LANES
        acc[i] ⊻= acc[i] >> 47
        acc[i] ⊻= grab(UInt64, secrets, i)
        acc[i] *= PRIME32_1
    end
end

function mergestate(acc::Accumulator, secret::AbstractVector{UInt8}, seed::UInt64)
    mix(a::UInt64, b::UInt64, secret::AbstractVector{UInt8}) =
        fold64(a ⊻ grab(UInt64, secret, 1), b ⊻ grab(UInt64, secret, 2))
    result = seed
    for i in 1:2:ACCUMULATOR_LANES-1
        result += mix(acc[i], acc[i+1], (@view secret[1+8*(i-1):end]))
    end
    result
end
