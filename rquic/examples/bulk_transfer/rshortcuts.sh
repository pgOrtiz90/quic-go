#!/bin/bash

#>

#>Directories for the testbed and source files (rQUIC examples).
RTSTBD="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd)"; export RTSTBD
#RSRC=$(realpath "$RTSTBD/.."); export RSRC
RSRC="$RTSTBD"
#>
#>These are the names of client and server files. Change them if you want to test other files.
export SRV_NAME="server_bulk"
export CLI_NAME="client_sink"
#>
#>Options that will be given to client and server programs.
log="" #-log"
debug="" #-debug"
export SRV_OPTS="-info $log $debug -wdir=\"$RTSTBD\" -timeout=5s # -trace"
export CLI_OPTS="-info $log $debug -wdir=\"$RTSTBD\" # -tcp"
#>



#>A simple help on functions available in this tool
alias rshortcuts_help='grep "#>\|alias\|function\|export" "$RTSTBD"/rshortcuts.sh | grep -v "export\ -f" | sed -e "s/#>//g" | grep -i --color -E "^|alias|function|export"' #|client|server|cli|srv"'
#>



function rbuildfull()
{
  #>Builds all *.go files in $RSRC and $RTSTBD.
  for f in $(cd "$RSRC" && ls ./*.go); do
    echo "COMPILING $f"
    go build -o "$RTSTBD" "$RSRC/$f"
    echo "FINISHED COMPILATION"
  done
  for f in $(cd "$RTSTBD" && ls ./*.go); do
    echo "COMPILING $f"
    go build -o "$RTSTBD" "$RTSTBD/$f"
    echo "FINISHED COMPILATION"
  done
}
export -f rbuildfull

function rbuildexp()
{
  #>Builds only $CLI_NAME and $SRV_NAME.
  for f in "$SRV_NAME.go" "$CLI_NAME.go"; do
    echo "COMPILING $f"
    go build -o "$RTSTBD" "$RSRC/$f"
    echo "FINISHED COMPILATION"
  done
}
export -f rbuildexp

alias rbuild='rbuildexp'
#>

function rrun()
{
  local srv="$RTSTBD/$SRV_NAME"
  local cli="$RTSTBD/$CLI_NAME"

  #>Executes $CLI_NAME and $SRV_NAME,
  echo "LAUNCHING $SRV_NAME"
  eval \""$srv"\" " $SRV_OPTS" > "$srv".log &
  pid_s=$!
  #echo $pid_s
  #sleep 2
  echo "LAUNCHING $CLI_NAME"
  eval \""$cli"\" " $CLI_OPTS" > "$cli".log &
  pid_c=$!
  #echo $pid_c
  #trap "kill $pid_s $pid_c; sleep 1" SIGINT
  trap "echo; kill %1 %2" SIGINT
  wait $pid_c
  wait $pid_s
  trap - SIGINT

  #>prints the output of both programs
  echo ""
  echo "--- $CLI_NAME.log ------------------------------"
  cat "$cli".log
  rm  "$cli".log
  printf "%0.s-" $(seq 1 ${#CLI_NAME})
  echo "------------------------------- end ---"
  echo ""
  echo "--- $SRV_NAME.log ------------------------------"
  cat "$srv".log
  rm  "$srv".log
  printf "%0.s-" $(seq 1 ${#SRV_NAME})
  echo "------------------------------- end ---"
  echo ""

  #>and merges programs' log files.
  if [ -z "$log" ] && [ -z "$debug" ]; then return; fi
  echo "MERGING LOGS"
  "$RTSTBD"/merge_logs -path="$RTSTBD"
}
export -f rrun
#>

alias rfull='rbuild; rrun'
#>

function  rlastn() { find "$RTSTBD" -name "$1*.log" | tail -$(("$2"+1)) | head -1 ; }
#>  rlastn [log name (prefix)] [N]
#>  Returns file name given log's prefix counting from the last log.
#>  Last log counts as zero. Default value of N is zero.
export -f rlastn
alias rlast='rlastn merged'
alias rlastcli='rlastn "$CLI_NAME"'
alias rlastsrv='rlastn "$SRV_NAME"'
#>

function  rcheckn() { vim "$(rlastn "$@")" ; }
#>  Opens the file returned by rlastn in vim.
export -f rcheckn
alias rcheck='rcheckn merged'
alias rcheckcli='rcheckn "$CLI_NAME"'
alias rchecksrv='rcheckn "$SRV_NAME"'
#>

function  rshown() { cat "$(rlastn "$@")" ; }
#>  Prints the file returned by rlastn using cat.
export -f rshown
alias rshow='rshown merged'
alias rshowcli='rshown "$CLI_NAME"'
alias rshowsrv='rshown "$SRV_NAME"'
#>

#>The following functions/aliases strongly depend on test programs' logging format.
function  rstats() { rshow "$1" | sed -n '/====================\\/,/\====================/p' ; }
export -f rstats
#>

function rlogrm()
{
  #>Removes last N log files. If no number is specified, removes all log files.
  if [ -z "$1" ]; then
    rm "$RTSTBD/"merged*.log
    rm "$RTSTBD/$CLI_NAME"*.log
    rm "$RTSTBD/$CLI_NAME"*.csv
    rm "$RTSTBD/$SRV_NAME"*.log
    rm "$RTSTBD/$SRV_NAME"*.csv
    return
  fi
  rm "$(find "$RTSTBD" -name "merged*.log"    | tail -"$1")"
  rm "$(find "$RTSTBD" -name "$CLI_NAME*.log" | tail -"$1")"
  rm "$(find "$RTSTBD" -name "$CLI_NAME*.csv" | tail -"$1")"
  rm "$(find "$RTSTBD" -name "$SRV_NAME*.log" | tail -"$1")"
  rm "$(find "$RTSTBD" -name "$SRV_NAME*.csv" | tail -"$1")"
}
export -f rlogrm
#>

