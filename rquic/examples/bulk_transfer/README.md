# Bulk transfer experiment for rQUIC

This folder contains code used for testing bulk transfer between endpoints with rQUIC. 

## rshortcuts.sh
Bash shortcuts to run and check experiments on localhost.
Was used to debug and check possible errors before starting a simulation campaign.
For loading these shortcuts, `cd` to this directory and run
```
sudo chmod +x rshortcuts.sh # if necessary
. ./rshortcuts.sh
```
After loading the file, you can see a brief help with
```
rshortcuts_help
```

## merge.go
Merges the outputs of client and server logged with rLogger in one file.

## sim_campaign_general.go
Reads from a _json_ file client and server configuration parameters to be tested, number of iterations and commands to launch the network environment and the endpoints.
If _json_ file could not be read, uses default values.

