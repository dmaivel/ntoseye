function display_base_address(args, current_process)
    local output = string.format("%x%x", current_process.base_address.high, current_process.base_address.low)
    print(output)
    return status_success()
end

base_addr = {} 
base_addr.on_load = function()
    return "display_base_address"
end