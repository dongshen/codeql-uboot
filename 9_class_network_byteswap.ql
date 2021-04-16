import cpp

class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists(MacroInvocation mi |
      mi.getMacroName().regexpMatch("ntoh(s|l|ll)") and
      this = mi.getExpr()
    )
  }
}

from NetworkByteSwap net
select net, "Network byte swap"