using Documenter, OAuth

makedocs()

deploydocs(
    deps = Deps.pip("mkdocs==0.16.3", "python-markdown-math", "mkdocs-bootswatch"),
    repo = "github.com/randyzwitch/OAuth.jl.git",
    julia  = "0.6",
    osname = "linux"
)
