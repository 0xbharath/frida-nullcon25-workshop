# Setup

Workshop repo is at *Repo Link* 

## Manual setup using Docker

1. Clone the workshop repo ``
2. Build the Docker container `docker build -t frida-workshop .`
3. Run the Docker container and get shell access `docker run -it --rm frida-workshop /bin/bash`
4. You can get additional shells on the Docker by running `docker exec <CONTAINER_ID> -it /bin/bash`

## Few points about the setup

1. You can work with bash shell inside the container but `tmux` is installed and preferred (https://tmuxcheatsheet.com/)
2. `~/exercises` directory on the container has all the hands-on exercises related files