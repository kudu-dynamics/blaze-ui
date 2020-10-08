goals:

X - demos that print out haskell code from PIL
- pipeline that takes PIL, prints haskell module, checks it with LH, returns result.
+ load support module (LH functions)
+ create temp file
+ check temp file with LH
+ get error report if failure


- add support for rest of PIL exprs to LH


- call graph


- taint analysis
+ Map var #{tainted by vars}
+ [Set vars] tainted var groups


- type inference
+ naive binja types
+ find equal pil var groups
  - Map PilVar (Set PilVar)
+ type inference based off of stdlib types


- solver
+ convert PIL to SBV
+ maybe need this instead of LH...


- loop analysis
+ find loops
+ find iterators
+ find things that change/update each iteration
