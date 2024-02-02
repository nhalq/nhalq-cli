#!/usr/bin/env zsh
# nhalq

_nhalq() {
  (( COMP_CWORD = CURRENT - 1))
  if [[ $COMP_CWORD -eq 1 ]]; then
    local -a subcmds
    subcmds=('vpn:openvpn3 connection'
             'reset-swap:reset swap space'
             'zdn:denoise id')
    _describe 'command' subcmds
  elif [[ $COMP_CWORD -eq 2 ]]; then
    # get second element of words
    case $words[2] in
      "vpn")
        local -a subcmds
        subcmds=('connect:create a new connection'
                 'disconnect:disconnect from a connection'
                 'status:show the status of a connection')
        _describe 'command' subcmds
        ;;
    esac
  fi
}

compdef _nhalq nhalq
