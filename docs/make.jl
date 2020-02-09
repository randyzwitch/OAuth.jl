using Documenter, OAuth

makedocs(
    sitename = "OAuth.jl"
)

deploydocs(
    deps = Deps.pip("mkdocs==0.16.3", "python-markdown-math", "mkdocs-bootswatch"),
    repo = "github.com/randyzwitch/OAuth.jl.git",
    julia  = "1.3",
    osname = "linux"
)
