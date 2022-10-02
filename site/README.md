# VeXation Site

* Hugo
* Nix (w/ flakes)
* Github pages

# Production

1. Setup nix.
1. Clone repo.
1. `cd site`
1. `nix build`
1. `nix run .#serve`

# Development

1. Setup nix.
1. Clone repo.
1. `cd site`
1. `nix develop`
1. `hugo server -D`

# Non-Nix Usage

1. Install Hugo
1. `cd site`
1. `git clone https://github.com/nodejh/hugo-theme-mini.git themes/mini`
1. `hugo server -D`
