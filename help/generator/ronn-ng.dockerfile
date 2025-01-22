FROM ruby:3.3.7-bookworm

RUN gem install ronn-ng
RUN apt-get update && apt-get install -y groff

ENV MANPAGER=cat

ENTRYPOINT ["/usr/local/bundle/bin/ronn"]
