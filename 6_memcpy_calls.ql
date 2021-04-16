import cpp

from FunctionCall call, Function func
where   
    call.getTarget() = func and
    func.getName() = "memcpy"
select call
