function list_arguments(args, current_process)
    for i = 1, args:size() do
        print(i .. ": " .. args:get(i))
    end
    
    return status_success()
end

list_args = {} 
list_args.on_load = function()
    return "list_arguments"
end