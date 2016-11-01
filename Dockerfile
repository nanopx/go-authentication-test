FROM golang:1.7.3

# Create workspace directory
RUN mkdir /workspace
WORKDIR /workspace

# Install glide v0.12.3
RUN wget https://github.com/Masterminds/glide/releases/download/v0.12.3/glide-v0.12.3-linux-386.tar.gz
RUN tar -zxvf glide-v0.12.3-linux-386.tar.gz
RUN mv linux-386/ glide/
ENV PATH /workspace/glide:$PATH
