FROM fuzzers/atheris:2.0.7-python3.9

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y git
# Build
ADD . /src
WORKDIR /src
RUN python3 -m pip install .

CMD /src/mayhem/fuzz_import.py
