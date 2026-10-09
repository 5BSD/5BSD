# Per-user interactive zsh settings; see zsh(1) and zshoptions(1).
# System defaults and completion are initialized by /etc/zshrc.
HISTFILE=${ZDOTDIR:-$HOME}/.zsh_history
HISTSIZE=1000
SAVEHIST=1000
setopt APPEND_HISTORY HIST_IGNORE_DUPS
