/**
 * @kind path-problem
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

// 通过定义NetworkByteSwap类来确定污染源是从ntoh相关的宏表达式发起的
class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists(MacroInvocation mi |
      mi.getMacroName().regexpMatch("ntoh(s|l|ll)") and
      this = mi.getExpr()
    )
  }
}

// 从污染追踪派生污染配置类
class Config extends TaintTracking::Configuration {
  Config() { this = "NetworkToMemFuncLength" }
  // 覆写污染源isSource
  override predicate isSource(DataFlow::Node source) { source.asExpr() instanceof NetworkByteSwap }
  // 覆写sink isSink, 进入memcpy的第二参数长度,memcpy(dest, src, sizeof(src));
  override predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call |
      call.getTarget().getName() = "memcpy" and
      sink.asExpr() = call.getArgument(2) and
      not call.getArgument(1).isConstant()
    )
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"