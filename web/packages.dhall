let upstream =
      https://github.com/purescript/package-sets/releases/download/psc-0.13.8-20200831/packages.dhall sha256:cdb3529cac2cd8dd780f07c80fd907d5faceae7decfcaa11a12037df68812c83

in upstream
   with foreign-generic =
    { dependencies =
        [ "assert"
        , "console"
        , "effect"
        , "exceptions"
        , "foreign"
        , "foreign-object"
        , "generics-rep"
        , "identity"
        , "rationals"
        , "quickcheck"
        , "test-unit"
        , "ordered-collections"
        , "proxy"
        , "psci-support"
        , "record"
        ]
    , repo =
        "https://github.com/mpdairy/purescript-foreign-generic.git"
    , version =
        "main"  -- branch, tag, or commit hash
    }


  with argonaut-aeson-generic =
    { dependencies =
        [ "argonaut"
        , "argonaut-codecs"
        , "argonaut-generic"
        , "console"
        , "effect"
        , "foreign-object"
        , "psci-support"
        , "test-unit"
        ]
    , repo =
        "https://github.com/coot/purescript-argonaut-aeson-generic.git"
    , version =
        "2fbd4c9ad3886dd3b8179765093aaae5773a5098"
    }
