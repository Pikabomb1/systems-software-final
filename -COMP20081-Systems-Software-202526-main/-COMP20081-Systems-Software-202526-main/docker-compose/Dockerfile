# Using a base image with VNC (Desktop Environment) support
FROM dorowu/ubuntu-desktop-lxde-vnc:focal

# --- FIX START ---
# Remove the broken Google Chrome repository list that causes the GPG error
RUN rm -f /etc/apt/sources.list.d/google-chrome.list
# --- FIX END ---

# Install Java (JDK 17) and Maven
RUN apt-get update && apt-get install -y \
    openjdk-17-jdk \
    maven \
    git \
    nano \
    && rm -rf /var/lib/apt/lists/*

# Set up the environment variables matching the docker-compose
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Create the user 'ntu-user' if it doesn't exist (base image uses root)
# then map the IDs to avoid permission issues
RUN useradd -m -u 1000 ntu-user || true
RUN echo "ntu-user:ntu-user" | chpasswd

# Set working directory

WORKDIR /home/ntu-user/cwk
