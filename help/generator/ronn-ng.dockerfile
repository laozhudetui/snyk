FROM ruby:4.0.1-trixie

RUN gem install ronn-ng
RUN apt-get update && apt-get install -y groff

ENV MANPAGER=cat

ENTRYPOINT ["/usr/local/bundle/bin/ronn"]
