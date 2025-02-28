# Setup

Workshop repo is at *Repo Link* 

## Manual setup using Docker

1. Clone the workshop repo ``
2. Build the Docker container `docker build -t frida-workshop .`
3. Run the Docker container and get shell access `docker run -it --rm frida-workshop /bin/bash`

## Setup using existing Docker image


## Few points about the setup

1. You can work with bash shell inside the container but `tmux` is installed and preferred (https://tmuxcheatsheet.com/)
2. `~/exercises` directory has all the hands-on exercises