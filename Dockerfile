FROM ubuntu:latest

# Set noninteractive mode for apt-get to avoid user prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update package lists and install necessary dependencies
RUN apt-get update && apt-get install -y \
    gdb \
    strace \
    ltrace \
    tmux \
    build-essential \
    git \
    libncurses5-dev \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Create a virtual environment and install frida-tools
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install frida-tools

# Clone the nSnake repository and install it
RUN git clone https://github.com/alexdantas/nSnake.git /opt/nsnake && \
    cd /opt/nsnake && \
    make && \
    make install

# Set the working directory to /opt/nsnake
WORKDIR /opt/nsnake

# Add the virtual environment to PATH
ENV PATH="/opt/venv/bin:$PATH"

ADD challenges /home/ubuntu/challenges

# Default command to open tmux on container start
CMD ["tmux"]
