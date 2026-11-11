# Public API

What the libraries of SharpICE expose is written down, and a removal from it does not build until it is written down too, an addition warns until it is. The libraries are SharpICE, SharpSTUN and SharpTURN,
and two checks run on every `dotnet build` of each:

- **The API files.** `PublicAPI.Shipped.txt` and `PublicAPI.Unshipped.txt` next to each project list
  its public types and members. They are the same on all four target frameworks. Shipped is the API
  as released; Unshipped is what changed since. A public symbol missing from them is a warning, RS0016, until it is
  listed - an addition breaks no one - and a listed one that is gone fails the build with RS0017.
- **Package validation.** Each package being built is checked for its target frameworks agreeing
  with one another: what netstandard2.0 offers, net472, net8.0 and net10.0 have to offer too. Once a
  library has a release, it is compared with that release as well, and every binary or source
  breaking change fails the build with a CP error.

## Adding to the API

List what the RS0016 warnings name: accept their fix in the IDE ("Add to public API"), or from the command line:

```
dotnet format analyzers src/SharpSTUN/SharpSTUN.csproj --diagnostics RS0016 --severity warn
```

The new lines land in that project's `PublicAPI.Unshipped.txt`.

A member that only some frameworks have, inside an `#if`, needs API files of its own for those
frameworks: a `PublicAPI/<framework>/` folder beside the project holding `PublicAPI.Shipped.txt` and
`PublicAPI.Unshipped.txt`, and those files added as `AdditionalFiles` for that framework, as
SharpSRTP and SharpDTLS do. Better still is to give it to the other frameworks too where they can
have it, rather than in place of something they already have, so that the frameworks keep agreeing.

## Removing or changing the API

RS0017 names what disappeared. Moving its line from Shipped to Unshipped with a `*REMOVED*` prefix
records the removal; a member whose signature changed is a removal of the old line and an addition
of the new one.

If package validation then reports a CP error, the change breaks code built against another
framework or, once there is one, the last release. When that is intended, record it:

```
dotnet build src/SharpSTUN/SharpSTUN.csproj -c Release -p:ApiCompatGenerateSuppressionFile=true
```

That writes `CompatibilitySuppressions.xml` next to the project. Say in the pull request what broke.

Validation runs as part of the build, because the build packs. `dotnet pack` on its own does not
rebuild and validates whatever binaries are already in `bin`.

## Releasing

1. Move every line of each library's `PublicAPI.Unshipped.txt` into the `PublicAPI.Shipped.txt`
   beside it, dropping the `*REMOVED*` lines together with the shipped lines they remove.
2. Once the release is on nuget.org, set `PackageValidationBaselineVersion` in each library's
   project to it (the first release adds the property), and delete or regenerate any
   `CompatibilitySuppressions.xml`.
