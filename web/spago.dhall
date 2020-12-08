{ name = "blaze-ui"
, dependencies =
  [ "aff-coroutines"
  , "avar"
  , "bigints"
  , "concur-react"
  , "console"
  , "effect"
  , "foreign-generic"
  , "generics-rep"
  , "halogen-hooks"
  , "interpolate"
  , "profunctor-lenses"
  , "psci-support"
  , "react-basic"
  , "react-basic-dom"
  , "react-basic-hooks"
  , "web-dom"
  , "web-html"
  , "web-socket"
  , "web-uievents"
  ]
, packages = ./packages.dhall
, sources = [ "src/**/*.purs", "test/**/*.purs", "gen/**/*.purs" ]
}
