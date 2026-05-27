#!lua name=waflib

redis.register_function(
    'rate_limit',
    function(keys, args)

        local key = keys[1]
        local limit = tonumber(args[1])
        local window = tonumber(args[2])

        local current = redis.call('INCR', key)

        if current == 1 then
            redis.call('EXPIRE', key, window)
        end

        if current > limit then
            return 0
        else
            return 1
        end
    end
)
