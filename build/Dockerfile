FROM lamw/vibauthor

# Copy all files to the container
COPY . acme-esxi

# Run VIB build script
RUN /bin/bash acme-esxi/build/create_vib.sh

CMD ["/bin/bash"]
